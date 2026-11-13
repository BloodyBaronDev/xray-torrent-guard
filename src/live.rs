//! Живой захват на Linux через AF_PACKET (без libpcap).
//!
//! Сокет SOCK_DGRAM отдаёт IP-пакет без L2-заголовка, поэтому работает
//! одинаково на Ethernet, TUN и WireGuard-интерфейсах.
use std::ffi::CString;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Capture {
    fd: i32,
    buf: Vec<u8>,
    /// Счётчики ядра (PACKET_STATISTICS), накопительно.
    pub received: u64,
    pub dropped: u64,
}

const SNAP: usize = 2048;

const ETH_P_ALL: u16 = 0x0003;

impl Capture {
    pub fn open(iface: &str) -> io::Result<Self> {
        let name = CString::new(iface).map_err(|_| io::Error::other("bad iface"))?;
        unsafe {
            let ifindex = libc::if_nametoindex(name.as_ptr());
            if ifindex == 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, (ETH_P_ALL).to_be() as i32);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = ETH_P_ALL.to_be();
            sll.sll_ifindex = ifindex as i32;
            let rc = libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            );
            if rc < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            // Больший буфер приёма сглаживает всплески. SO_RCVBUF урезается до
            // net.core.rmem_max (обычно ~200 КБ), поэтому от root берём FORCE.
            let sz: libc::c_int = 16 << 20;
            let p = &sz as *const _ as *const libc::c_void;
            let l = std::mem::size_of::<libc::c_int>() as u32;
            if libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, p, l) < 0 {
                libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, p, l);
            }
            // детекторам нужны первые сотни байт: копируем не больше SNAP
            Ok(Self { fd, buf: vec![0u8; SNAP], received: 0, dropped: 0 })
        }
    }

    /// Следующий IP-пакет: (время в мкс, данные).
    pub fn next(&mut self) -> io::Result<(u64, &[u8])> {
        loop {
            let n = unsafe { libc::recv(self.fd, self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0);
            let n = (n as usize).min(self.buf.len());
            return Ok((ts, &self.buf[..n]));
        }
    }
}

impl Capture {
    /// Обновить счётчики ядра. Чтение сбрасывает их в ядре, поэтому накапливаем.
    pub fn update_stats(&mut self) {
        let mut st: libc::tpacket_stats = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(self.fd, libc::SOL_PACKET, libc::PACKET_STATISTICS, &mut st as *mut _ as *mut libc::c_void, &mut len)
        };
        if rc == 0 {
            self.received += st.tp_packets as u64;
            self.dropped += st.tp_drops as u64;
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
