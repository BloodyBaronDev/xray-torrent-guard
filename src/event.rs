//! Событие обнаружения и его JSON-представление (без serde).
use crate::engine::{Score, SubjectId};
use crate::packet::L4;
use std::fmt::Write;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct Event {
    /// Порядковый номер, назначается при публикации.
    pub id: u64,
    pub ts_us: u64,
    pub subject: SubjectId,
    pub score: u32,
    pub reasons: Vec<(&'static str, usize)>,
    pub l4: L4,
    /// Пир, на котором сработал порог.
    pub remote: IpAddr,
}

impl Event {
    pub fn new(ts_us: u64, s: Score, l4: L4, remote: IpAddr) -> Self {
        Self { id: 0, ts_us, subject: s.subject, score: s.score, reasons: s.reasons, l4, remote }
    }

    pub fn to_json(&self) -> String {
        let mut o = String::with_capacity(256);
        let _ = write!(o, "{{\"id\":{},\"ts\":{}.{:06},\"type\":\"torrent_detected\",", self.id, self.ts_us / 1_000_000, self.ts_us % 1_000_000);
        subject_json(&mut o, &self.subject);
        let _ = write!(
            o,
            ",\"score\":{},\"proto\":\"{}\",\"remote\":\"{}\",",
            self.score,
            if self.l4 == L4::Tcp { "tcp" } else { "udp" },
            self.remote
        );
        reasons_json(&mut o, &self.reasons);
        o.push('}');
        o
    }
}

pub fn score_json(s: &Score) -> String {
    let mut o = String::from("{");
    subject_json(&mut o, &s.subject);
    let _ = write!(o, ",\"score\":{},", s.score);
    reasons_json(&mut o, &s.reasons);
    o.push('}');
    o
}

fn subject_json(o: &mut String, s: &SubjectId) {
    o.push_str("\"subject\":");
    esc(o, &s.to_string());
    let _ = write!(o, ",\"subject_kind\":\"{}\"", s.kind());
}

fn reasons_json(o: &mut String, r: &[(&'static str, usize)]) {
    o.push_str("\"reasons\":{");
    for (i, (n, c)) in r.iter().enumerate() {
        let _ = write!(o, "{}\"{}\":{}", if i > 0 { "," } else { "" }, n, c);
    }
    o.push('}');
}

/// Строка JSON с экранированием (email из лога — внешние данные).
pub fn esc(o: &mut String, s: &str) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_user() {
        let s = Score { subject: SubjectId::User("a\"b\\c\n".into()), score: 1, reasons: vec![] };
        assert_eq!(score_json(&s), "{\"subject\":\"a\\\"b\\\\c\\u000a\",\"subject_kind\":\"user\",\"score\":1,\"reasons\":{}}");
    }
}
