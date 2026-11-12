//! Движок: учёт потоков, накопление сигналов по субъекту, оценка риска.
//!
//! Субъект — пользователь Xray (если поток сопоставлен по access-логу)
//! или IP инициатора потока (TUN/WireGuard). Каждый сигнал учитывается
//! по числу разных удалённых пиров в скользящем окне.
use crate::event::Event;
use crate::packet::{Packet, L4};
use crate::proto::{classify, Signal};
use crate::xray::SharedIndex;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SubjectId {
    Ip(IpAddr),
    User(Arc<str>),
}

impl SubjectId {
    pub fn kind(&self) -> &'static str {
        match self {
            SubjectId::Ip(_) => "ip",
            SubjectId::User(_) => "user",
        }
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectId::Ip(ip) => ip.fmt(f),
            SubjectId::User(u) => f.write_str(u),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Порог оценки для события.
    pub threshold: u32,
    /// Окно учёта сигналов, секунды.
    pub window_secs: u64,
    /// Число разных UDP-пиров в окне, после которого добавляется сигнал веера.
    pub fanout_peers: usize,
    /// Вес сигнала веера.
    pub fanout_weight: u32,
    /// Потолок вклада одного слабого сигнала.
    pub weak_cap: u32,
    /// Не повторять событие по субъекту чаще, секунды.
    pub cooldown_secs: u64,
    /// Время простоя TCP-потока до удаления, секунды.
    pub flow_idle_secs: u64,
    /// Время простоя UDP-потока (DHT/uTP создают их тысячами), секунды.
    pub udp_idle_secs: u64,
    /// Максимум потоков в памяти (защита от переполнения).
    pub max_flows: usize,
    /// Сколько секунд от начала потока пытаться найти его пользователя в логе.
    pub attribution_retry_secs: u64,
    /// Учитывать только потоки, сопоставленные с пользователем.
    pub only_attributed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 100,
            window_secs: 60,
            fanout_peers: 40,
            fanout_weight: 50,
            // слабый сигнал сам доходит до порога: uTP — от 5 пиров, MSE — от 10
            weak_cap: 100,
            cooldown_secs: 60,
            flow_idle_secs: 60,
            udp_idle_secs: 30,
            max_flows: 200_000,
            attribution_retry_secs: 3,
            only_attributed: false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    l4: L4,
    a: SocketAddr,
    b: SocketAddr,
}

impl FlowKey {
    fn of(p: &Packet) -> Self {
        let (a, b) = if p.src <= p.dst { (p.src, p.dst) } else { (p.dst, p.src) };
        Self { l4: p.l4, a, b }
    }
}

struct Flow {
    /// Инициатор — сторона `a` ключа.
    init_a: bool,
    fwd_payload: bool,
    rev_payload: bool,
    start_us: u64,
    last_us: u64,
    user: Option<Arc<str>>,
}

const PEER_CAP: usize = 1024;
const KINDS: usize = Signal::ALL.len();

#[derive(Default)]
struct Subject {
    /// По каждому виду сигнала: удалённый пир → время последнего появления.
    seen: [HashMap<IpAddr, u64>; KINDS],
    udp_peers: HashMap<IpAddr, u64>,
    last_event_us: Option<u64>,
}

impl Subject {
    fn prune(&mut self, cutoff: u64) {
        for m in self.seen.iter_mut() {
            m.retain(|_, &mut t| t >= cutoff);
        }
        self.udp_peers.retain(|_, &mut t| t >= cutoff);
    }

    fn empty(&self) -> bool {
        self.udp_peers.is_empty() && self.seen.iter().all(|m| m.is_empty())
    }
}

/// Текущая оценка субъекта.
#[derive(Clone, Debug)]
pub struct Score {
    pub subject: SubjectId,
    pub score: u32,
    /// (имя сигнала, число разных пиров)
    pub reasons: Vec<(&'static str, usize)>,
}

pub struct Engine {
    pub cfg: Config,
    flows: HashMap<FlowKey, Flow>,
    subjects: HashMap<SubjectId, Subject>,
    xray: Option<SharedIndex>,
    last_gc_us: u64,
    pub packets: u64,
    pub attributed_flows: u64,
    /// Новые потоки, пропущенные из-за переполнения таблицы.
    pub dropped_flows: u64,
    last_pressure_us: u64,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            flows: HashMap::new(),
            subjects: HashMap::new(),
            xray: None,
            last_gc_us: 0,
            packets: 0,
            attributed_flows: 0,
            dropped_flows: 0,
            last_pressure_us: 0,
        }
    }

    /// Включить сопоставление потоков с пользователями по access-логу Xray.
    pub fn with_xray(mut self, idx: SharedIndex) -> Self {
        self.xray = Some(idx);
        self
    }

    /// Обработать пакет; вернуть событие, если субъект пересёк порог.
    pub fn process(&mut self, p: &Packet) -> Option<Event> {
        self.packets += 1;
        let now = p.ts_us;
        if now.saturating_sub(self.last_gc_us) > 5_000_000 {
            self.gc(now);
        }

        let key = FlowKey::of(p);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.cfg.max_flows {
                // давление: раз в секунду вытесняем потоки, простаивающие дольше 5 с
                if now.saturating_sub(self.last_pressure_us) >= 1_000_000 {
                    self.last_pressure_us = now;
                    self.flows.retain(|_, f| now.saturating_sub(f.last_us) < 5_000_000);
                }
                if self.flows.len() >= self.cfg.max_flows {
                    self.dropped_flows += 1;
                    return None;
                }
            }
            // Инициатор — первый увиденный отправитель (для TCP это обычно SYN).
            self.flows.insert(
                key,
                {
                    // TCP, пойманный с середины: первые пакеты уже прошли, сигнатуры начала не ищем
                    let mid = p.l4 == L4::Tcp && !p.syn;
                    Flow { init_a: p.src == key.a, fwd_payload: mid, rev_payload: mid, start_us: now, last_us: now, user: None }
                },
            );
        }
        let flow = self.flows.get_mut(&key).unwrap();
        flow.last_us = now;
        let fwd = (p.src == key.a) == flow.init_a;
        let first = if p.payload.is_empty() {
            false
        } else if fwd {
            !std::mem::replace(&mut flow.fwd_payload, true)
        } else {
            !std::mem::replace(&mut flow.rev_payload, true)
        };
        let (local, remote) = if fwd { (p.src, p.dst) } else { (p.dst, p.src) };

        // Владелец потока по логу Xray: ищем, пока поток молодой.
        if flow.user.is_none() {
            if let Some(idx) = &self.xray {
                if now.saturating_sub(flow.start_us) <= self.cfg.attribution_retry_secs * 1_000_000 {
                    flow.user = idx.lock().unwrap().lookup(p.l4, remote, now);
                    if flow.user.is_some() {
                        self.attributed_flows += 1;
                    }
                }
            }
        }
        let subject = match &flow.user {
            Some(u) => SubjectId::User(u.clone()),
            None if self.cfg.only_attributed => return None,
            None => SubjectId::Ip(local.ip()),
        };
        let remote = remote.ip();

        let sig = classify(p, first);
        let udp_out = p.l4 == L4::Udp && fwd;
        if sig.is_none() && !udp_out {
            return None;
        }
        let s = self.subjects.entry(subject.clone()).or_default();
        if udp_out && (s.udp_peers.len() < PEER_CAP || s.udp_peers.contains_key(&remote)) {
            s.udp_peers.insert(remote, now);
        }
        if let Some(sig) = sig {
            let m = &mut s.seen[sig.index()];
            if m.len() < PEER_CAP || m.contains_key(&remote) {
                m.insert(remote, now);
            }
        } else if s.udp_peers.len() < self.cfg.fanout_peers {
            return None;
        }

        let score = score_of(&self.cfg, subject, s);
        if score.score < self.cfg.threshold {
            return None;
        }
        let cooldown = self.cfg.cooldown_secs * 1_000_000;
        if s.last_event_us.is_some_and(|t| now.saturating_sub(t) < cooldown) {
            return None;
        }
        s.last_event_us = Some(now);
        Some(Event::new(now, score, p.l4, remote))
    }

    /// Оценки всех субъектов с ненулевым счётом.
    pub fn scores(&self) -> Vec<Score> {
        let mut v: Vec<Score> = self
            .subjects
            .iter()
            .map(|(id, s)| score_of(&self.cfg, id.clone(), s))
            .filter(|s| s.score > 0)
            .collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.score));
        v
    }

    fn gc(&mut self, now: u64) {
        self.last_gc_us = now;
        let (tcp, udp) = (self.cfg.flow_idle_secs * 1_000_000, self.cfg.udp_idle_secs * 1_000_000);
        self.flows.retain(|k, f| now.saturating_sub(f.last_us) < if k.l4 == L4::Udp { udp } else { tcp });
        let cutoff = now.saturating_sub(self.cfg.window_secs * 1_000_000);
        self.subjects.retain(|_, s| {
            s.prune(cutoff);
            !s.empty() || s.last_event_us.is_some_and(|t| t >= cutoff)
        });
    }
}

fn score_of(cfg: &Config, subject: SubjectId, s: &Subject) -> Score {
    let mut total = 0u32;
    let mut reasons = Vec::new();
    for sig in Signal::ALL {
        let n = s.seen[sig.index()].len();
        if n == 0 {
            continue;
        }
        let w = if sig.strong() { sig.weight() } else { (sig.weight() * n as u32).min(cfg.weak_cap) };
        total += w;
        reasons.push((sig.name(), n));
    }
    let fan = s.udp_peers.len();
    if fan >= cfg.fanout_peers {
        total += cfg.fanout_weight;
        reasons.push(("udp_fanout", fan));
    }
    Score { subject, score: total, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::{parse_line, Index};
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    fn pkt<'a>(l4: L4, src: ([u8; 4], u16), dst: ([u8; 4], u16), ts: u64, payload: &'a [u8]) -> Packet<'a> {
        Packet {
            ts_us: ts,
            l4,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src.0)), src.1),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst.0)), dst.1),
            syn: false,
            payload,
        }
    }

    fn ip(a: [u8; 4]) -> SubjectId {
        SubjectId::Ip(IpAddr::V4(Ipv4Addr::from(a)))
    }

    const DHT_R: &[u8] = b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re";

    #[test]
    fn handshake_triggers_event() {
        let mut e = Engine::new(Config::default());
        let mut hs = b"\x13BitTorrent protocol".to_vec();
        hs.extend_from_slice(&[0; 48]);
        let ev = e.process(&pkt(L4::Tcp, ([10, 0, 0, 2], 50000), ([1, 2, 3, 4], 6881), 1, &hs)).expect("event");
        assert_eq!(ev.subject, ip([10, 0, 0, 2]));
        // повтор внутри cooldown — без события
        assert!(e.process(&pkt(L4::Tcp, ([10, 0, 0, 2], 50001), ([1, 2, 3, 5], 6881), 2, &hs)).is_none());
    }

    #[test]
    fn reply_attributed_to_initiator() {
        let mut e = Engine::new(Config::default());
        assert!(e.process(&pkt(L4::Udp, ([10, 0, 0, 3], 40000), ([5, 5, 5, 5], 6881), 1, b"hello")).is_none());
        let ev = e.process(&pkt(L4::Udp, ([5, 5, 5, 5], 6881), ([10, 0, 0, 3], 40000), 2, DHT_R)).expect("event");
        assert_eq!(ev.subject, ip([10, 0, 0, 3]));
    }

    #[test]
    fn xray_users_are_separated() {
        let mut idx = Index::default();
        for (u, dst) in [("alice", "5.5.5.5:6881"), ("bob", "6.6.6.6:443")] {
            let l = format!("2024/01/01 00:00:00 from 9.9.9.9:1 accepted udp:{dst} [in >> direct] email: {u}");
            idx.insert(&parse_line(&l).unwrap(), 1_000_000);
        }
        let idx = Arc::new(Mutex::new(idx));
        let mut e = Engine::new(Config { only_attributed: true, ..Config::default() }).with_xray(idx);
        let srv = [203, 0, 113, 10];
        // bob: обычный QUIC, alice: DHT — оба идут с IP сервера
        assert!(e.process(&pkt(L4::Udp, (srv, 40001), ([6, 6, 6, 6], 443), 1_000_100, b"\xc0quic")).is_none());
        let ev = e.process(&pkt(L4::Udp, (srv, 40000), ([5, 5, 5, 5], 6881), 1_000_200, DHT_R)).expect("event");
        assert_eq!(ev.subject, SubjectId::User("alice".into()));
        assert!(ev.to_json().contains("\"subject\":\"alice\",\"subject_kind\":\"user\""));
        // поток без строки в логе при only_attributed игнорируется
        assert!(e.process(&pkt(L4::Udp, (srv, 40002), ([7, 7, 7, 7], 6881), 1_000_300, DHT_R)).is_none());
        assert_eq!(e.attributed_flows, 2);
    }

    #[test]
    fn single_utp_is_not_enough_but_many_are() {
        let mut e = Engine::new(Config::default());
        let mut s = vec![0x41, 0, 0x12, 0x34];
        s.extend_from_slice(&[0; 8]);
        s.extend_from_slice(&0x0010_0000u32.to_be_bytes());
        s.extend_from_slice(&[0, 1, 0, 0]);
        assert!(e.process(&pkt(L4::Udp, ([10, 0, 0, 4], 40000), ([9, 9, 9, 1], 6881), 1, &s)).is_none());
        let mut got = None;
        for i in 2..60u8 {
            got = got.or(e.process(&pkt(L4::Udp, ([10, 0, 0, 4], 40000), ([9, 9, 9, i], 6881), i as u64, &s)));
        }
        let ev = got.expect("utp + fanout");
        assert!(ev.reasons.iter().any(|(n, _)| *n == "utp"));
    }

    fn noise(len: usize, x: &mut u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                *x ^= *x << 13;
                *x ^= *x >> 7;
                *x ^= *x << 17;
                (*x >> 24) as u8
            })
            .collect()
    }

    /// Входящие туннели на ноду: Hysteria2 (QUIC/Salamander, port hopping),
    /// XHTTP/WS через CDN (TLS с сотен адресов CDN), Shadowsocks (случайный первый пакет).
    #[test]
    fn inbound_tunnels_are_quiet() {
        let mut e = Engine::new(Config::default());
        let node = [203, 0, 113, 10];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01];
        hello.extend(noise(506, &mut x));
        for i in 0..200_000u64 {
            let ts = i * 50;
            // Hysteria2: 20 клиентов, порты сервера 20000..20999, случайные байты 20..1400
            let c = (i % 20) as u8;
            let len = 20 + (x % 1380) as usize;
            let pl = noise(len, &mut x);
            let hop = 20000 + (x % 1000) as u16;
            let (src, dst) = (([198, 51, 100, c], 40000 + c as u16), (node, hop));
            let p = if i % 3 == 0 { pkt(L4::Udp, dst, src, ts, &pl) } else { pkt(L4::Udp, src, dst, ts, &pl) };
            assert!(e.process(&p).is_none(), "hysteria: {:?}", e.scores().first());
            // CDN → нода: новые TLS-соединения с 250 адресов
            if i % 10 == 0 {
                let cdn = [104, 16, (i / 10 % 250) as u8, 1];
                let mut syn = pkt(L4::Tcp, (cdn, 30000 + (i % 30000) as u16), (node, 443), ts, &[]);
                syn.syn = true;
                assert!(e.process(&syn).is_none());
                let p = pkt(L4::Tcp, (cdn, 30000 + (i % 30000) as u16), (node, 443), ts + 1, &hello);
                assert!(e.process(&p).is_none());
            }
            // Shadowsocks/VLESS-encryption: первый пакет — шум 96..608 байт
            if i % 7 == 0 {
                let len = 96 + (x % 512) as usize;
                let pl = noise(len, &mut x);
                let mut syn = pkt(L4::Tcp, ([198, 51, 100, 200], 1024 + (i % 60000) as u16), (node, 8388), ts, &[]);
                syn.syn = true;
                e.process(&syn);
                let p = pkt(L4::Tcp, ([198, 51, 100, 200], 1024 + (i % 60000) as u16), (node, 8388), ts + 1, &pl);
                assert!(e.process(&p).is_none());
            }
        }
        let worst = e.scores().into_iter().map(|s| s.score).max().unwrap_or(0);
        assert!(worst < 50, "максимальная оценка {worst}");
    }

    #[test]
    fn ordinary_traffic_is_quiet() {
        let mut e = Engine::new(Config::default());
        let http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        for i in 0..30u8 {
            assert!(e.process(&pkt(L4::Tcp, ([10, 0, 0, 5], 50000 + i as u16), ([93, 184, 216, i], 443), i as u64, http)).is_none());
            assert!(e.process(&pkt(L4::Udp, ([10, 0, 0, 5], 53000), ([8, 8, 8, 8], 53), i as u64, b"\x12\x34\x01\x00\x00\x01")).is_none());
        }
        assert!(e.scores().is_empty());
    }
}
