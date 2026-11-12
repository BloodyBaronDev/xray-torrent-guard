//! Сквозной тест: pcap в памяти → парсер → движок.
use std::io::Cursor;
use xray_torrent_guard::engine::{Config, Engine};
use xray_torrent_guard::packet;
use xray_torrent_guard::pcap::PcapReader;

fn ipv4_udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    f.extend_from_slice(&[2, 0, 4, 0]);
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&65535u32.to_le_bytes());
    f.extend_from_slice(&101u32.to_le_bytes()); // LINKTYPE_RAW
    for (i, fr) in frames.iter().enumerate() {
        f.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
        f.extend_from_slice(&0u32.to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(&(fr.len() as u32).to_le_bytes());
        f.extend_from_slice(fr);
    }
    f
}

#[test]
fn dht_in_pcap_detected_and_dns_is_not() {
    let dht = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    let frames = vec![
        ipv4_udp([10, 8, 0, 2], 53000, [1, 1, 1, 1], 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
        ipv4_udp([10, 8, 0, 3], 6881, [87, 98, 162, 88], 6881, dht),
    ];
    let mut rd = PcapReader::new(Cursor::new(pcap(&frames))).unwrap();
    let mut eng = Engine::new(Config::default());
    let link = rd.link;
    let mut events = Vec::new();
    while let Some((ts, fr)) = rd.next_frame().unwrap() {
        let p = packet::parse(link, ts, fr).expect("parse");
        events.extend(eng.process(&p));
    }
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].subject.to_string(), "10.8.0.3");
    assert!(events[0].to_json().contains("\"dht\":1"));
}
