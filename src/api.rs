//! Выходы для внешних систем: HTTP API, webhook и внешняя команда.
//!
//! API намеренно минимальный, чтобы любой мог подключить свою панель/бота/фаервол:
//!   GET /health            → {"status":"ok","packets":N,...}
//!   GET /v1/events?since=N → массив событий с id > N (кольцевой буфер)
//!   GET /v1/subjects       → текущие оценки субъектов
use crate::engine::Score;
use crate::event::{score_json, Event};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const RING: usize = 1000;

#[derive(Default)]
pub struct Shared {
    pub events: VecDeque<Event>,
    pub next_id: u64,
    pub scores: Vec<Score>,
    pub packets: u64,
    /// Дополнительные поля для /health (готовый JSON-фрагмент без скобок).
    pub extra: String,
}

pub type State = Arc<Mutex<Shared>>;

/// Куда отправлять события.
pub struct Sinks {
    pub state: State,
    pub stdout: bool,
    tx: Option<SyncSender<Event>>,
}

impl Sinks {
    pub fn new(stdout: bool, webhook: Option<String>, exec: Option<String>) -> Self {
        let tx = (webhook.is_some() || exec.is_some()).then(|| {
            // Доставка в отдельном потоке, чтобы не тормозить анализ.
            let (tx, rx) = sync_channel::<Event>(256);
            std::thread::spawn(move || {
                for ev in rx {
                    if let Some(url) = &webhook {
                        if let Err(e) = post_json(url, &ev.to_json()) {
                            eprintln!("xtg: webhook: {e}");
                        }
                    }
                    if let Some(cmd) = &exec {
                        run_exec(cmd, &ev);
                    }
                }
            });
            tx
        });
        Self { state: State::default(), stdout, tx }
    }

    pub fn publish(&self, mut ev: Event) {
        {
            let mut s = self.state.lock().unwrap();
            s.next_id += 1;
            ev.id = s.next_id;
            if s.events.len() == RING {
                s.events.pop_front();
            }
            s.events.push_back(ev.clone());
        }
        if self.stdout {
            println!("{}", ev.to_json());
        }
        if let Some(tx) = &self.tx {
            if let Err(TrySendError::Full(_)) = tx.try_send(ev) {
                eprintln!("xtg: очередь доставки переполнена, событие пропущено");
            }
        }
    }
}

/// Запуск внешней команды; данные события — в переменных окружения.
fn run_exec(cmd: &str, ev: &Event) {
    let reasons: Vec<String> = ev.reasons.iter().map(|(n, c)| format!("{n}:{c}")).collect();
    let mut c = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", cmd]);
        c
    } else {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", cmd]);
        c
    };
    let r = c
        .env("XTG_SUBJECT", ev.subject.to_string())
        .env("XTG_SUBJECT_KIND", ev.subject.kind())
        .env("XTG_SCORE", ev.score.to_string())
        .env("XTG_REMOTE", ev.remote.to_string())
        .env("XTG_REASONS", reasons.join(","))
        .env("XTG_EVENT", ev.to_json())
        .status();
    if let Err(e) = r {
        eprintln!("xtg: exec: {e}");
    }
}

/// POST JSON на http:// адрес (без TLS — для локальных обработчиков).
pub fn post_json(url: &str, body: &str) -> std::io::Result<()> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("поддерживается только http:// (для https поставьте локальный прокси)"))?;
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let addr = if host.contains(':') { host.to_string() } else { format!("{host}:80") };
    let sa = addr.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("адрес не найден"))?;
    let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(5))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line)?;
    if !line.split(' ').nth(1).is_some_and(|c| c.starts_with('2')) {
        return Err(std::io::Error::other(format!("ответ: {}", line.trim())));
    }
    Ok(())
}

/// HTTP API в отдельном потоке. Рекомендуется слушать только 127.0.0.1.
pub fn serve(addr: &str, state: State) -> std::io::Result<()> {
    let l = TcpListener::bind(addr)?;
    std::thread::spawn(move || {
        for conn in l.incoming().flatten() {
            let _ = handle(conn, &state);
        }
    });
    Ok(())
}

fn handle(mut s: TcpStream, state: &State) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    // заголовки читаем и отбрасываем
    let mut h = String::new();
    while r.read_line(&mut h)? > 2 {
        h.clear();
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (code, body) = if method != "GET" {
        ("405 Method Not Allowed", "{\"error\":\"method\"}".to_string())
    } else {
        route(path, query, state)
    };
    write!(
        s,
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn route(path: &str, query: &str, state: &State) -> (&'static str, String) {
    let st = state.lock().unwrap();
    match path {
        "/health" => (
            "200 OK",
            format!("{{\"status\":\"ok\",\"version\":\"{}\",\"packets\":{}{}}}", env!("CARGO_PKG_VERSION"), st.packets, st.extra),
        ),
        "/v1/events" => {
            let since: u64 = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let items: Vec<String> = st.events.iter().filter(|e| e.id > since).map(|e| e.to_json()).collect();
            ("200 OK", format!("[{}]", items.join(",")))
        }
        "/v1/subjects" => {
            let items: Vec<String> = st.scores.iter().map(score_json).collect();
            ("200 OK", format!("[{}]", items.join(",")))
        }
        _ => ("404 Not Found", "{\"error\":\"not found\"}".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Score, SubjectId};
    use crate::packet::L4;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn events_since() {
        let sinks = Sinks::new(false, None, None);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..3 {
            let s = Score { subject: SubjectId::Ip(ip), score: 100, reasons: vec![("dht", 1)] };
            sinks.publish(Event::new(1_500_000, s, L4::Udp, ip));
        }
        let (c, b) = route("/v1/events", "since=2", &sinks.state);
        assert_eq!(c, "200 OK");
        assert!(b.contains("\"id\":3") && !b.contains("\"id\":2"));
        assert!(b.contains("\"reasons\":{\"dht\":1}"));
        assert_eq!(route("/nope", "", &sinks.state).0, "404 Not Found");
    }
}
