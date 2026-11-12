//! Чтение классического pcap (без libpcap).
use crate::packet::LinkType;
use std::io::{self, Read};

pub struct PcapReader<R: Read> {
    r: R,
    swap: bool,
    nanos: bool,
    pub link: LinkType,
    buf: Vec<u8>,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut r: R) -> io::Result<Self> {
        let mut h = [0u8; 24];
        r.read_exact(&mut h)?;
        let magic = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let (swap, nanos) = match magic {
            0xa1b2c3d4 => (false, false),
            0xd4c3b2a1 => (true, false),
            0xa1b23c4d => (false, true),
            0x4d3cb2a1 => (true, true),
            0x0a0d0d0a => return Err(bad("pcapng не поддерживается: конвертируйте `editcap -F pcap`")),
            _ => return Err(bad("не pcap-файл")),
        };
        let lt = rd32(&h[20..24], swap) & 0x0fff_ffff;
        let link = LinkType::from_pcap(lt).ok_or_else(|| bad(&format!("linktype {lt} не поддерживается")))?;
        Ok(Self { r, swap, nanos, link, buf: Vec::with_capacity(65536) })
    }

    /// Следующий кадр: (время в мкс, данные). None — конец файла.
    pub fn next_frame(&mut self) -> io::Result<Option<(u64, &[u8])>> {
        let mut h = [0u8; 16];
        match self.r.read_exact(&mut h) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let sec = rd32(&h[0..4], self.swap) as u64;
        let frac = rd32(&h[4..8], self.swap) as u64;
        let incl = rd32(&h[8..12], self.swap) as usize;
        if incl > 262_144 {
            return Err(bad("слишком большой кадр"));
        }
        self.buf.resize(incl, 0);
        self.r.read_exact(&mut self.buf)?;
        let us = sec * 1_000_000 + if self.nanos { frac / 1000 } else { frac };
        Ok(Some((us, &self.buf)))
    }
}

fn rd32(b: &[u8], swap: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if swap { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
}
