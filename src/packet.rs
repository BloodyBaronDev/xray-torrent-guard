//! Разбор L2/L3/L4 до полезной нагрузки TCP/UDP.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum L4 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    /// Время в микросекундах (unix).
    pub ts_us: u64,
    pub l4: L4,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Для TCP: флаг SYN (без ACK) — начало соединения.
    pub syn: bool,
    pub payload: &'a [u8],
}

/// Тип канального уровня (значения linktype из pcap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Raw,
    LinuxSll,
    LinuxSll2,
}

impl LinkType {
    pub fn from_pcap(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Ethernet),
            101 | 12 | 14 => Some(Self::Raw),
            113 => Some(Self::LinuxSll),
            276 => Some(Self::LinuxSll2),
            _ => None,
        }
    }
}

pub fn parse(link: LinkType, ts_us: u64, frame: &[u8]) -> Option<Packet<'_>> {
    let ip = match link {
        LinkType::Raw => frame,
        LinkType::Ethernet => {
            let mut off = 12;
            let mut et = be16(frame, off)?;
            // VLAN-теги 802.1Q/802.1ad
            while et == 0x8100 || et == 0x88a8 {
                off += 4;
                et = be16(frame, off)?;
            }
            if et != 0x0800 && et != 0x86dd {
                return None;
            }
            frame.get(off + 2..)?
        }
        LinkType::LinuxSll => frame.get(16..)?,
        LinkType::LinuxSll2 => frame.get(20..)?,
    };
    parse_ip(ts_us, ip)
}

pub fn parse_ip(ts_us: u64, ip: &[u8]) -> Option<Packet<'_>> {
    let ver = ip.first()? >> 4;
    let (proto, src, dst, l4) = match ver {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            let total = be16(ip, 2)? as usize;
            // фрагменты кроме первого пропускаем
            if be16(ip, 6)? & 0x1fff != 0 {
                return None;
            }
            let end = total.min(ip.len());
            let src = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip.get(12..16)?).ok()?));
            let dst = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip.get(16..20)?).ok()?));
            (ip[9], src, dst, ip.get(ihl..end)?)
        }
        6 => {
            let plen = be16(ip, 4)? as usize;
            let mut next = *ip.get(6)?;
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip.get(8..24)?).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip.get(24..40)?).ok()?));
            let mut body = ip.get(40..(40 + plen).min(ip.len()))?;
            // цепочка заголовков расширения
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        next = *body.first()?;
                        let len = (*body.get(1)? as usize + 1) * 8;
                        body = body.get(len..)?;
                    }
                    44 => {
                        next = *body.first()?;
                        if be16(body, 2)? & 0xfff8 != 0 {
                            return None;
                        }
                        body = body.get(8..)?;
                    }
                    _ => break,
                }
            }
            (next, src, dst, body)
        }
        _ => return None,
    };
    match proto {
        6 => {
            let doff = ((*l4.get(12)? >> 4) as usize) * 4;
            let flags = *l4.get(13)?;
            Some(Packet {
                ts_us,
                l4: L4::Tcp,
                src: SocketAddr::new(src, be16(l4, 0)?),
                dst: SocketAddr::new(dst, be16(l4, 2)?),
                syn: flags & 0x02 != 0 && flags & 0x10 == 0,
                payload: l4.get(doff..).unwrap_or(&[]),
            })
        }
        17 => Some(Packet {
            ts_us,
            l4: L4::Udp,
            src: SocketAddr::new(src, be16(l4, 0)?),
            dst: SocketAddr::new(dst, be16(l4, 2)?),
            syn: false,
            payload: l4.get(8..(be16(l4, 4)? as usize).clamp(8, l4.len()))?,
        }),
        _ => None,
    }
}

#[inline]
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}
