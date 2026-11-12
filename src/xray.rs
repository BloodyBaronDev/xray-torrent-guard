//! Сопоставление потоков с пользователями Xray по access-логу.
//!
//! Нода открывает исходящее соединение к адресу из строки лога
//! `... from 1.2.3.4:5678 accepted tcp:5.6.7.8:6881 [in >> out] email: user`,
//! поэтому пакет с удалённым адресом 5.6.7.8:6881 относим к `user`.
//! Если в логе домен (sniffing подменил адрес), сопоставить пакет нельзя —
//! такие строки только считаются.
use crate::packet::L4;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Время из строки в мкс, если удалось разобрать (местное время Xray).
    pub ts_us: Option<u64>,
    pub l4: L4,
    pub host: Host,
    pub port: u16,
    /// email клиента, а без него — IP клиента.
    pub user: String,
}

/// Разбор одной строки access-лога. Не-«accepted» строки дают None.
pub fn parse_line(line: &str) -> Option<LogEntry> {
    let (head, tail) = line.split_once(" accepted ")?;
    let from = head.rsplit_once(" from ")?.1.trim();
    let mut it = tail.split_whitespace();
    let dest = it.next()?;
    let (l4, rest) = if let Some(r) = dest.strip_prefix("tcp:") {
        (L4::Tcp, r)
    } else if let Some(r) = dest.strip_prefix("udp:") {
        (L4::Udp, r)
    } else {
        (L4::Tcp, dest)
    };
    let (host, port) = split_host_port(rest)?;
    let host = match host.parse::<IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(host.to_ascii_lowercase()),
    };
    let user = match tail.split_once("email: ") {
        Some((_, e)) if !e.trim().is_empty() => e.trim().to_string(),
        _ => {
            let f = from.strip_prefix("tcp:").or_else(|| from.strip_prefix("udp:")).unwrap_or(from);
            split_host_port(f).map(|(h, _)| h.to_string()).unwrap_or_else(|| f.to_string())
        }
    };
    Some(LogEntry { ts_us: parse_ts(line), l4, host, port, user })
}

fn split_host_port(s: &str) -> Option<(&str, u16)> {
    if let Some(r) = s.strip_prefix('[') {
        let (h, p) = r.split_once("]:")?;
        return Some((h, p.parse().ok()?));
    }
    let (h, p) = s.rsplit_once(':')?;
    Some((h, p.parse().ok()?))
}

/// `2024/05/05 12:00:00[.ffffff]` → мкс от эпохи, считая время UTC.
fn parse_ts(line: &str) -> Option<u64> {
    let mut it = line.split_whitespace();
    let (d, t) = (it.next()?, it.next()?);
    let mut dp = d.split('/').map(|x| x.parse::<i64>().ok());
    let (y, m, day) = (dp.next()??, dp.next()??, dp.next()??);
    let (hms, frac) = t.split_once('.').unwrap_or((t, "0"));
    let mut tp = hms.split(':').map(|x| x.parse::<i64>().ok());
    let (hh, mm, ss) = (tp.next()??, tp.next()??, tp.next()??);
    let us: i64 = format!("{:0<6}", &frac[..frac.len().min(6)]).parse().ok()?;
    // days_from_civil (H. Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    u64::try_from(secs * 1_000_000 + us).ok()
}

const SLOTS: usize = 2;

#[derive(Default, Clone)]
struct Slot {
    users: [(Option<Arc<str>>, u64); SLOTS],
}

/// Индекс «(протокол, адрес назначения) → последние пользователи».
pub struct Index {
    map: HashMap<(L4, IpAddr, u16), Slot>,
    users: HashMap<String, Arc<str>>,
    /// Сколько секунд держать запись.
    pub ttl_us: u64,
    pub max_entries: usize,
    pub lines: u64,
    pub matched_lines: u64,
    pub domain_lines: u64,
    /// Строки, отброшенные из-за переполнения индекса.
    pub dropped_lines: u64,
    last_prune_us: u64,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            users: HashMap::new(),
            // поток сопоставляется в первые секунды, а Xray пишет строку на каждое соединение,
            // поэтому старые записи не нужны
            ttl_us: 30_000_000,
            max_entries: 500_000,
            lines: 0,
            matched_lines: 0,
            domain_lines: 0,
            dropped_lines: 0,
            last_prune_us: 0,
        }
    }
}

impl Index {
    pub fn insert(&mut self, e: &LogEntry, ts_us: u64) {
        self.lines += 1;
        let ip = match e.host {
            Host::Ip(ip) => ip,
            Host::Domain(_) => {
                self.domain_lines += 1;
                return;
            }
        };
        self.matched_lines += 1;
        if self.map.len() >= self.max_entries {
            // полная чистка не чаще раза в секунду, иначе O(n) на каждую строку
            if ts_us.saturating_sub(self.last_prune_us) >= 1_000_000 {
                self.prune(ts_us);
            }
            if self.map.len() >= self.max_entries {
                self.dropped_lines += 1;
                return;
            }
        }
        let user = match self.users.get(&e.user) {
            Some(u) => u.clone(),
            None => {
                let u: Arc<str> = e.user.as_str().into();
                self.users.insert(e.user.clone(), u.clone());
                u
            }
        };
        let slot = self.map.entry((e.l4, ip, e.port)).or_default();
        // тот же пользователь — обновляем время, иначе вытесняем самую старую запись
        let i = slot
            .users
            .iter()
            .position(|(u, _)| u.as_deref() == Some(&*user))
            .unwrap_or_else(|| (0..SLOTS).min_by_key(|&i| slot.users[i].0.as_ref().map_or(0, |_| slot.users[i].1 + 1)).unwrap());
        slot.users[i] = (Some(user), ts_us);
    }

    /// Пользователь, чья строка лога ближе всего предшествует пакету.
    pub fn lookup(&self, l4: L4, remote: SocketAddr, ts_us: u64) -> Option<Arc<str>> {
        const SLACK: u64 = 5_000_000; // лог мог прийти чуть позже пакета
        let slot = self.map.get(&(l4, remote.ip(), remote.port()))?;
        let live = || slot.users.iter().filter_map(|(u, t)| u.as_ref().map(|u| (u, *t)));
        // последняя строка до пакета; если её нет — ближайшая чуть после (лог опоздал)
        live()
            .filter(|&(_, t)| t <= ts_us && ts_us - t <= self.ttl_us)
            .max_by_key(|&(_, t)| t)
            .or_else(|| live().filter(|&(_, t)| t > ts_us && t <= ts_us + SLACK).min_by_key(|&(_, t)| t))
            .map(|(u, _)| u.clone())
    }

    pub fn prune(&mut self, now_us: u64) {
        self.last_prune_us = now_us;
        let ttl = self.ttl_us;
        self.map.retain(|_, s| {
            for u in s.users.iter_mut() {
                if now_us.saturating_sub(u.1) > ttl {
                    *u = (None, 0);
                }
            }
            s.users.iter().any(|u| u.0.is_some())
        });
        self.users.retain(|_, u| Arc::strong_count(u) > 1);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

pub type SharedIndex = Arc<Mutex<Index>>;

pub fn now_us() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// Загрузить весь лог (для `analyze`). Время берётся из строк со сдвигом `utc_offset_s`.
pub fn load_file(path: &str, utc_offset_s: i64, idx: &mut Index) -> std::io::Result<()> {
    let r = BufReader::new(File::open(path)?);
    idx.ttl_us = u64::MAX / 4; // офлайн: не вытесняем по времени
    for line in r.lines() {
        let line = line?;
        if let Some(e) = parse_line(&line) {
            let ts = e.ts_us.map(|t| (t as i64 - utc_offset_s * 1_000_000).max(0) as u64).unwrap_or(0);
            idx.insert(&e, ts);
        }
    }
    Ok(())
}

/// Параметры слежения за логом.
#[derive(Clone, Debug, Default)]
pub struct FollowOpts {
    /// Усекать файл до нуля, когда прочитано больше стольких байт.
    /// Xray открывает лог с O_APPEND, поэтому продолжит писать с начала файла.
    pub truncate_at: Option<u64>,
}

#[derive(Default)]
pub struct FollowStats {
    pub truncations: u64,
    pub reopens: u64,
}

/// Следить за логом в фоне (как `tail -F`), время — момент прочтения строки.
pub fn follow(path: impl Into<PathBuf>, idx: SharedIndex, opts: FollowOpts) -> Arc<Mutex<FollowStats>> {
    let path = path.into();
    let stats = Arc::new(Mutex::new(FollowStats::default()));
    let st = stats.clone();
    std::thread::spawn(move || {
        let mut from_start = false;
        loop {
            match follow_once(&path, &idx, &opts, from_start, &st) {
                Ok(()) => st.lock().unwrap().reopens += 1,
                Err(e) => eprintln!("xtg: xray-лог {}: {e}", path.display()),
            }
            // после ротации новый файл читаем с начала
            from_start = true;
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    stats
}

fn follow_once(path: &PathBuf, idx: &SharedIndex, opts: &FollowOpts, from_start: bool, st: &Mutex<FollowStats>) -> std::io::Result<()> {
    let mut f = File::open(path)?;
    let mut pos = if from_start { 0 } else { f.seek(SeekFrom::End(0))? };
    let mut r = BufReader::with_capacity(1 << 16, f);
    let mut line = Vec::with_capacity(512);
    let mut last_prune = now_us();
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line)?;
        if n > 0 && line.ends_with(b"\n") {
            pos += n as u64;
            if let Some(e) = parse_line(&String::from_utf8_lossy(&line)) {
                idx.lock().unwrap().insert(&e, now_us());
            }
            continue;
        }
        if n > 0 {
            // неполная строка: вернуться к её началу и дождаться конца
            r.seek(SeekFrom::Start(pos))?;
        }
        if let Some(limit) = opts.truncate_at {
            if pos >= limit {
                // всё прочитано до EOF — усекаем; строки, дописанные в этот миг, теряются
                std::fs::OpenOptions::new().write(true).open(path)?.set_len(0)?;
                pos = 0;
                r.seek(SeekFrom::Start(0))?;
                st.lock().unwrap().truncations += 1;
                continue;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        // ротация или усечение снаружи: файл по пути стал короче прочитанного
        if std::fs::metadata(path).map(|m| m.len() < pos).unwrap_or(true) {
            return Ok(());
        }
        let now = now_us();
        if now - last_prune > 5_000_000 {
            last_prune = now;
            idx.lock().unwrap().prune(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follow_truncates_and_survives_rotation() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("xtg-follow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("access.log");
        let mut w = std::fs::OpenOptions::new().create(true).append(true).open(&path).unwrap();
        let idx: SharedIndex = Arc::new(Mutex::new(Index::default()));
        let st = follow(&path, idx.clone(), FollowOpts { truncate_at: Some(4096) });
        std::thread::sleep(Duration::from_millis(300));
        for i in 0..200u32 {
            writeln!(w, "2024/01/01 00:00:00 from 1.1.1.1:1 accepted udp:10.0.{}.{}:6881 [a >> b] email: u{i}", i / 250, i % 250).unwrap();
            if i % 20 == 0 {
                std::thread::sleep(Duration::from_millis(150));
            }
        }
        w.write_all(b"\xff\xfe garbage\n").unwrap();
        std::thread::sleep(Duration::from_millis(600));
        // внешняя ротация: файл заменён новым
        drop(w);
        std::fs::remove_file(&path).unwrap();
        let mut w = std::fs::File::create(&path).unwrap();
        writeln!(w, "2024/01/01 00:00:00 from 1.1.1.1:1 accepted tcp:10.9.9.9:1 [a >> b] email: after").unwrap();
        std::thread::sleep(Duration::from_millis(1200));
        let lines = idx.lock().unwrap().lines;
        let size = std::fs::metadata(&path).unwrap().len();
        let tr = st.lock().unwrap().truncations;
        let _ = std::fs::remove_dir_all(&dir);
        assert!(tr >= 1, "не было усечения");
        assert!(lines >= 195, "прочитано {lines} из 201");
        assert!(idx.lock().unwrap().lookup(L4::Tcp, "10.9.9.9:1".parse().unwrap(), now_us()).is_some(), "строка после ротации потеряна");
        assert!(size < 4096);
    }

    #[test]
    fn parse_variants() {
        let a = parse_line("2024/05/05 12:00:00.123456 from tcp:1.2.3.4:5678 accepted tcp:5.6.7.8:6881 [vless-in -> direct] email: alice@node").unwrap();
        assert_eq!(a.l4, L4::Tcp);
        assert_eq!(a.host, Host::Ip("5.6.7.8".parse().unwrap()));
        assert_eq!(a.port, 6881);
        assert_eq!(a.user, "alice@node");
        assert_eq!(a.ts_us, Some(1_714_910_400_123_456));

        let b = parse_line("2023/06/01 10:00:00 from 1.2.3.4:5678 accepted udp:[2a00:1450::1]:443 [in >> out] email: 7.bob").unwrap();
        assert_eq!(b.l4, L4::Udp);
        assert_eq!(b.host, Host::Ip("2a00:1450::1".parse().unwrap()));
        assert_eq!(b.user, "7.bob");

        let c = parse_line("2023/06/01 10:00:00 from [2001:db8::5]:999 accepted tcp:tracker.example.org:80 [in >> out]").unwrap();
        assert_eq!(c.host, Host::Domain("tracker.example.org".into()));
        assert_eq!(c.user, "2001:db8::5");

        assert!(parse_line("2023/06/01 10:00:00 from 1.2.3.4:1 rejected  proxy/vless: invalid user").is_none());
        assert!(parse_line("[Info] app/dispatcher: sniffed domain").is_none());
    }

    #[test]
    fn index_lookup_latest_user() {
        let mut idx = Index::default();
        let dst: SocketAddr = "5.6.7.8:6881".parse().unwrap();
        let mk = |u: &str| parse_line(&format!("2024/01/01 00:00:00 from 1.1.1.1:1 accepted udp:5.6.7.8:6881 [a >> b] email: {u}")).unwrap();
        idx.insert(&mk("alice"), 10_000_000);
        idx.insert(&mk("bob"), 20_000_000);
        assert_eq!(idx.lookup(L4::Udp, dst, 15_000_000).as_deref(), Some("alice"));
        assert_eq!(idx.lookup(L4::Udp, dst, 21_000_000).as_deref(), Some("bob"));
        assert!(idx.lookup(L4::Tcp, dst, 21_000_000).is_none());
        assert!(idx.lookup(L4::Udp, dst, 1_000_000_000).is_none()); // истёк ttl
        idx.prune(1_000_000_000);
        assert!(idx.is_empty());
    }
}
