//! Синтетическая нагрузка: N клиентов за Xray, из них T качают торренты.
//! cargo run --release --example load -- 1000 50 60
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use xray_torrent_guard::engine::{Config, Engine};
use xray_torrent_guard::packet::{Packet, L4};
use xray_torrent_guard::xray::{parse_line, Index};

fn main() {
    let a: Vec<u64> = std::env::args().skip(1).map(|x| x.parse().unwrap()).collect();
    let (users, torr, secs) = (a.first().copied().unwrap_or(1000), a.get(1).copied().unwrap_or(50), a.get(2).copied().unwrap_or(60));
    let srv = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 0);
    let idx = Arc::new(Mutex::new(Index::default()));
    let mut eng = Engine::new(Config { only_attributed: true, ..Config::default() }).with_xray(idx.clone());

    let dht = b"d1:ad2:id20:abcdefghij0123456789e1:q9:get_peers1:t2:aa1:y1:qe".to_vec();
    let mut utp = vec![0x01u8, 0, 0x12, 0x34];
    utp.extend_from_slice(&[0; 8]);
    utp.extend_from_slice(&0x0010_0000u32.to_be_bytes());
    utp.extend_from_slice(&[0, 1, 0, 0]);
    utp.extend_from_slice(&[0xab; 1000]);
    let tls = vec![0x17u8, 0x03, 0x03, 0x05, 0x00].into_iter().chain(std::iter::repeat_n(0x5a, 1200)).collect::<Vec<_>>();

    let mut rng = 0x1234_5678u64;
    let mut rnd = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let peer = |r: u64| SocketAddr::new(IpAddr::V4(Ipv4Addr::from((r as u32) | 0x0100_0000)), 1024 + (r >> 40) as u16 % 60000);

    let mut log_lines = 0u64;
    let mut events = 0u64;
    let mut pkts = 0u64;
    let mut port = 1024u16;
    let mut nextport = || {
        port = port.wrapping_add(1).max(1024);
        port
    };
    // постоянные HTTPS-потоки обычных клиентов: по 5 на человека
    let normal: Vec<(String, SocketAddr, SocketAddr)> = (0..users - torr)
        .flat_map(|u| (0..5).map(move |k| (u, k)))
        .map(|(u, _)| (format!("user{u}"), SocketAddr::new(srv.ip(), 0), SocketAddr::new(IpAddr::V4(Ipv4Addr::new(142, 250, (u % 250) as u8, 1)), 443)))
        .collect();
    let started = Instant::now();
    let log = |idx: &Mutex<Index>, user: &str, l4: &str, dst: SocketAddr, ts: u64| {
        let l = format!("2024/01/01 00:00:00 from 198.51.100.1:1 accepted {l4}:{dst} [in >> direct] email: {user}");
        idx.lock().unwrap().insert(&parse_line(&l).unwrap(), ts);
    };
    for (u, _, dst) in &normal {
        log(&idx, u, "tcp", *dst, 0);
        log_lines += 1;
    }
    let mut normal_ports: Vec<u16> = normal.iter().map(|_| nextport()).collect();

    for sec in 0..secs {
        let base = sec * 1_000_000;
        if sec % 5 == 0 {
            idx.lock().unwrap().prune(base); // как в follow()
        }
        // обычные клиенты: 1000 пакетов/с на всех внутри уже открытых потоков (≈ 10 Мбит/с)
        // и 2 новых потока в секунду на человека
        for i in 0..(users - torr) * 100 {
            let n = (rnd() as usize) % normal.len();
            let (_, _, dst) = &normal[n];
            let p = Packet { ts_us: base + i, l4: L4::Tcp, src: *dst, dst: SocketAddr::new(srv.ip(), normal_ports[n]), syn: false, payload: &tls };
            eng.process(&p);
            pkts += 1;
        }
        for u in 0..users - torr {
            for _ in 0..2 {
                let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(151, 101, (u % 250) as u8, (rnd() % 250) as u8)), 443);
                log(&idx, &format!("user{u}"), "tcp", dst, base);
                log_lines += 1;
                let p = Packet { ts_us: base + 1, l4: L4::Tcp, src: SocketAddr::new(srv.ip(), nextport()), dst, syn: true, payload: &[] };
                eng.process(&p);
                pkts += 1;
            }
        }
        normal_ports.iter_mut().for_each(|_| {});
        // торрент-клиенты: 50 новых DHT-узлов/с, 20 новых uTP-пиров/с, 300 пакетов данных/с
        for t in 0..torr {
            let user = format!("torr{t}");
            let mut flows = Vec::new();
            for k in 0..70 {
                let dst = peer(rnd());
                log(&idx, &user, "udp", dst, base);
                log_lines += 1;
                let pl: &[u8] = if k < 50 { &dht } else { &utp };
                let p = Packet { ts_us: base + 2, l4: L4::Udp, src: SocketAddr::new(srv.ip(), nextport()), dst, syn: false, payload: pl };
                if eng.process(&p).is_some() {
                    events += 1;
                }
                pkts += 1;
                if k >= 50 {
                    flows.push((p.src, dst));
                }
            }
            for i in 0..300 {
                let (s, d) = flows[i % flows.len()];
                eng.process(&Packet { ts_us: base + 3, l4: L4::Udp, src: d, dst: s, syn: false, payload: &utp });
                pkts += 1;
            }
        }
    }
    let el = started.elapsed().as_secs_f64();
    let flagged = eng.scores().iter().filter(|s| s.score >= 100).count();
    let fp = eng.scores().iter().filter(|s| s.subject.to_string().starts_with("user")).count();
    let i = idx.lock().unwrap();
    println!("симулировано {secs} с: пакетов {pkts} ({:.0}/с), строк лога {log_lines} ({:.0}/с)", pkts as f64 / secs as f64, log_lines as f64 / secs as f64);
    println!("время обработки {el:.2} с → {:.0} пакетов/с на ядро (вместе с логом)", pkts as f64 / el);
    println!("событий {events}, торрентщиков выше порога сейчас {flagged}/{torr}, ложных среди обычных {fp}");
    println!("индекс лога {} записей (отброшено строк {}), потоков сопоставлено {}, потоков пропущено {}", i.len(), i.dropped_lines, eng.attributed_flows, eng.dropped_flows);
}
