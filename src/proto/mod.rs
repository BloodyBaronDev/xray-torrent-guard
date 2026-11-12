//! Сигнатурные детекторы протоколов BitTorrent по полезной нагрузке.
//!
//! Каждый детектор смотрит на одну полезную нагрузку и возвращает сигнал.
//! «Сильные» сигналы однозначны, «слабые» требуют подтверждения поведением.
use crate::packet::{Packet, L4};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Открытый handshake пира: `\x13BitTorrent protocol`.
    BtHandshake,
    /// DHT-запрос/ответ KRPC (bencode-словарь с `y`=q|r|e).
    Dht,
    /// HTTP-announce/scrape к трекеру.
    HttpTracker,
    /// UDP-трекер (BEP 15): connect/announce.
    UdpTracker,
    /// Local Service Discovery (BEP 14).
    Lsd,
    /// Заголовок uTP (BEP 29). Слабый: короткие заголовки бывают случайно.
    Utp,
    /// Кандидат MSE/PE: первый пакет TCP высокой энтропии длиной 96..=608.
    MseCandidate,
}

impl Signal {
    pub const ALL: [Signal; 7] = [
        Signal::BtHandshake,
        Signal::Dht,
        Signal::HttpTracker,
        Signal::UdpTracker,
        Signal::Lsd,
        Signal::Utp,
        Signal::MseCandidate,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Signal::BtHandshake => "bt_handshake",
            Signal::Dht => "dht",
            Signal::HttpTracker => "http_tracker",
            Signal::UdpTracker => "udp_tracker",
            Signal::Lsd => "lsd",
            Signal::Utp => "utp",
            Signal::MseCandidate => "mse_candidate",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }

    /// Вклад в оценку риска (порог по умолчанию — 100).
    pub fn weight(self) -> u32 {
        match self {
            Signal::BtHandshake | Signal::Dht | Signal::UdpTracker | Signal::Lsd | Signal::HttpTracker => 100,
            Signal::Utp => 20,
            Signal::MseCandidate => 10,
        }
    }

    pub fn strong(self) -> bool {
        self.weight() >= 100
    }
}

/// `first` — первая полезная нагрузка в данном направлении потока.
pub fn classify(p: &Packet, first: bool) -> Option<Signal> {
    let d = p.payload;
    if d.is_empty() {
        return None;
    }
    match p.l4 {
        L4::Tcp => {
            if is_bt_handshake(d) {
                Some(Signal::BtHandshake)
            } else if first && is_http_tracker(d) {
                Some(Signal::HttpTracker)
            } else if first && !well_known_port(p.src.port()) && !well_known_port(p.dst.port()) && is_mse_candidate(d) {
                Some(Signal::MseCandidate)
            } else {
                None
            }
        }
        L4::Udp => {
            if is_dht(d) {
                Some(Signal::Dht)
            } else if is_udp_tracker(d) {
                Some(Signal::UdpTracker)
            } else if is_lsd(d) {
                Some(Signal::Lsd)
            } else if is_bt_handshake(d) {
                // handshake внутри полезной нагрузки uTP
                Some(Signal::BtHandshake)
            } else if is_utp(d) {
                Some(Signal::Utp)
            } else {
                None
            }
        }
    }
}

const PSTR: &[u8] = b"\x13BitTorrent protocol";

pub fn is_bt_handshake(d: &[u8]) -> bool {
    d.starts_with(PSTR) || (d.len() >= 20 + PSTR.len() && find(&d[20..], PSTR).is_some())
}

pub fn is_dht(d: &[u8]) -> bool {
    if d.len() < 12 || d[0] != b'd' || d[d.len() - 1] != b'e' {
        return false;
    }
    let y = find(d, b"1:y1:").and_then(|i| d.get(i + 5).copied());
    matches!(y, Some(b'q' | b'r' | b'e')) && find(d, b"1:t").is_some() && valid_bencode(d)
}

pub fn is_http_tracker(d: &[u8]) -> bool {
    if !d.starts_with(b"GET ") {
        return false;
    }
    let line = &d[..find(d, b"\r\n").unwrap_or(d.len().min(4096))];
    find(line, b"info_hash=").is_some() && (find(line, b"peer_id=").is_some() || find(line, b"/scrape").is_some())
}

pub fn is_udp_tracker(d: &[u8]) -> bool {
    const MAGIC: [u8; 8] = 0x41727101980u64.to_be_bytes();
    if d.len() == 16 && d[..8] == MAGIC && d[8..12] == [0, 0, 0, 0] {
        return true; // connect request
    }
    // announce request (BEP 15): 98 байт, action=1, порт в конце ненулевой
    // Проверяем и поля event (0..=3) и num_want (-1 или разумное число): иначе
    // DNS-ответ с ARCOUNT=1 (EDNS) даёт те же байты 8..12 = 00 00 00 01.
    if !(98..=120).contains(&d.len()) || d[8..12] != [0, 0, 0, 1] || d[..8].iter().all(|&b| b == 0) || d[96..98] == [0, 0] {
        return false;
    }
    let event = u32::from_be_bytes([d[80], d[81], d[82], d[83]]);
    let num_want = i32::from_be_bytes([d[92], d[93], d[94], d[95]]);
    event <= 3 && (num_want == -1 || (0..=1000).contains(&num_want))
}

pub fn is_lsd(d: &[u8]) -> bool {
    d.starts_with(b"BT-SEARCH * HTTP/1.1") && find(d, b"Infohash:").is_some()
}

pub fn is_utp(d: &[u8]) -> bool {
    if d.len() < 20 {
        return false;
    }
    // STUN (WebRTC): тот же первый байт бывает, но всегда есть magic cookie
    if d[4..8] == [0x21, 0x12, 0xa4, 0x42] {
        return false;
    }
    let (ty, ver) = (d[0] >> 4, d[0] & 0x0f);
    if ver != 1 || ty > 4 {
        return false;
    }
    // Цепочка расширений должна корректно заканчиваться внутри пакета.
    let mut ext = d[1];
    let mut off = 20;
    while ext != 0 {
        if ext > 4 {
            return false;
        }
        let (Some(&n), Some(&l)) = (d.get(off), d.get(off + 1)) else { return false };
        ext = n;
        off += 2 + l as usize;
        if off > d.len() {
            return false;
        }
    }
    let wnd = u32::from_be_bytes([d[12], d[13], d[14], d[15]]);
    match ty {
        4 => off == d.len() && wnd > 0, // ST_SYN без данных
        2 => off == d.len(),            // ST_STATE: только заголовок
        3 => true,                      // ST_RESET
        _ => wnd > 0,                   // ST_DATA/ST_FIN
    }
}

pub fn is_mse_candidate(d: &[u8]) -> bool {
    // Ya/Yb (96 байт DH) + случайный паддинг 0..512
    if !(96..=608).contains(&d.len()) || known_plaintext(d) {
        return false;
    }
    let mut seen = [false; 256];
    for &b in d {
        seen[b as usize] = true;
    }
    let distinct = seen.iter().filter(|&&x| x).count() as f64;
    // ожидаемое число разных байтов у равномерно случайных данных длины n
    let expected = 256.0 * (1.0 - (255.0f64 / 256.0).powi(d.len() as i32));
    distinct >= 0.85 * expected
}

/// Начала известных открытых протоколов, которые не могут быть MSE.
fn known_plaintext(d: &[u8]) -> bool {
    matches!(d, [0x16, 0x03, ..] | [0x17, 0x03, ..] | [0x14, 0x03, ..])
        || [&b"GET "[..], b"POST", b"HEAD", b"PUT ", b"CONN", b"SSH-", b"HTTP", b"PRI "]
            .iter()
            .any(|p| d.starts_with(p))
}

/// Порты обычных сервисов: шифрованный первый пакет там не признак торрента.
pub fn well_known_port(p: u16) -> bool {
    matches!(p, 22 | 53 | 80 | 443 | 465 | 587 | 853 | 993 | 995 | 5222 | 5223 | 8080 | 8443)
}

/// Энтропия Шеннона в битах на байт.
pub fn entropy(d: &[u8]) -> f64 {
    let mut c = [0u32; 256];
    for &b in d {
        c[b as usize] += 1;
    }
    let n = d.len() as f64;
    c.iter()
        .filter(|&&x| x > 0)
        .map(|&x| {
            let p = x as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Буфер — ровно одно корректное bencode-значение.
pub fn valid_bencode(d: &[u8]) -> bool {
    fn val(d: &[u8], mut i: usize, depth: u8) -> Option<usize> {
        if depth > 32 {
            return None;
        }
        match *d.get(i)? {
            b'i' => {
                i += 1;
                let s = i;
                while *d.get(i)? != b'e' {
                    if !(d[i].is_ascii_digit() || (d[i] == b'-' && i == s)) {
                        return None;
                    }
                    i += 1;
                }
                (i > s).then_some(i + 1)
            }
            b'l' | b'd' => {
                let dict = d[i] == b'd';
                i += 1;
                while *d.get(i)? != b'e' {
                    if dict && !d[i].is_ascii_digit() {
                        return None;
                    }
                    i = val(d, i, depth + 1)?;
                    if dict {
                        i = val(d, i, depth + 1)?;
                    }
                }
                Some(i + 1)
            }
            b'0'..=b'9' => {
                let mut n = 0usize;
                while *d.get(i)? != b':' {
                    n = n.checked_mul(10)?.checked_add((d[i] as char).to_digit(10)? as usize)?;
                    i += 1;
                }
                let end = i + 1 + n;
                (end <= d.len()).then_some(end)
            }
            _ => None,
        }
    }
    val(d, 0, 0) == Some(d.len())
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn noise(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 8) as u8
            })
            .collect()
    }

    #[test]
    fn handshake() {
        let mut h = PSTR.to_vec();
        h.extend_from_slice(&[0u8; 48]);
        assert!(is_bt_handshake(&h));
        assert!(!is_bt_handshake(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn dht_ping() {
        assert!(is_dht(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"));
        assert!(is_dht(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"));
        assert!(!is_dht(b"d1:y1:qe garbage"));
        assert!(!is_dht(b"{\"y\":\"q\",\"t\":1}"));
    }

    #[test]
    fn http_tracker() {
        assert!(is_http_tracker(
            b"GET /announce?info_hash=%12%34&peer_id=-qB4500-abc&port=6881 HTTP/1.1\r\nHost: t\r\n\r\n"
        ));
        assert!(!is_http_tracker(b"GET /index.html?info_hash=x HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn udp_tracker_connect() {
        let mut c = 0x41727101980u64.to_be_bytes().to_vec();
        c.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3, 4]);
        assert!(is_udp_tracker(&c));
        assert!(!is_udp_tracker(&[0u8; 16]));
        // настоящий announce
        let mut a = vec![0x5au8; 98];
        a[8..12].copy_from_slice(&[0, 0, 0, 1]);
        a[80..84].copy_from_slice(&2u32.to_be_bytes());
        a[92..96].copy_from_slice(&(-1i32).to_be_bytes());
        a[96..98].copy_from_slice(&6881u16.to_be_bytes());
        assert!(is_udp_tracker(&a));
        // DNS-ответ dl.google.com с EDNS, снят на реальной ноде
        let dns = hex("7b248180000100040000000102646c06676f6f676c6503636f6d0000010001c00c000100010000002c00048efa66bec00c000100010000002c00048efa665dc00c000100010000002c00048efa665bc00c000100010000002c00048efa66880000290 4d0000000000000");
        assert_eq!(dns.len(), 106);
        assert!(!is_udp_tracker(&dns));
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn lsd() {
        assert!(is_lsd(b"BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: abc\r\n\r\n\r\n"));
    }

    #[test]
    fn utp_syn() {
        let mut s = vec![0x41, 0, 0x12, 0x34];
        s.extend_from_slice(&[0; 8]);
        s.extend_from_slice(&0x0010_0000u32.to_be_bytes());
        s.extend_from_slice(&[0, 1, 0, 0]);
        assert!(is_utp(&s));
        let mut bad = s.clone();
        bad[0] = 0x42;
        assert!(!is_utp(&bad));
    }

    #[test]
    fn mse_vs_text() {
        let r = noise(300, 0x9e3779b9);
        assert!(is_mse_candidate(&r));
        assert!(!is_mse_candidate(&[b'a'; 200]));
        assert!(!is_mse_candidate(&r[..50]));
    }

    #[test]
    fn bencode() {
        assert!(valid_bencode(b"d3:fooi42e3:barl1:a1:bee"));
        assert!(!valid_bencode(b"d3:fooi42e"));
        assert!(!valid_bencode(b"5:abc"));
        assert!(!valid_bencode(b"ie"));
    }
}
