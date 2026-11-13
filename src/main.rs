use std::fs::File;
use std::io::BufReader;
use std::process::ExitCode;
use xray_torrent_guard::api::{self, Sinks};
use xray_torrent_guard::engine::{Config, Engine};
use xray_torrent_guard::event::score_json;
use xray_torrent_guard::packet;
use xray_torrent_guard::pcap::PcapReader;
use xray_torrent_guard::xray::{self, Index, SharedIndex};
use std::sync::{Arc, Mutex};

const USAGE: &str = "xtg — Xray Torrent Guard

Использование:
  xtg analyze <file.pcap> [опции]   разобрать запись, события в stdout (JSON Lines)
  xtg run --iface <dev> [опции]     живой захват (Linux, нужен CAP_NET_RAW)

Опции:
  --threshold N      порог оценки (по умолчанию 100)
  --window S         окно учёта сигналов, сек (60)
  --fanout N         порог веера UDP-пиров (40)
  --cooldown S       не чаще одного события на субъекта за S сек (60)
  --api ADDR         HTTP API, например 127.0.0.1:9090
  --webhook URL      POST каждого события на http://...
  --exec CMD         команда на событие (env: XTG_SUBJECT, XTG_SCORE, XTG_REMOTE, XTG_REASONS, XTG_EVENT)
  --quiet            не печатать события в stdout
  --events-file PATH хранить события в файле (JSON Lines), чтобы API пережил перезапуск

Xray:
  --xray-log PATH        access-лог Xray: события по пользователю (email) вместо IP
  --xray-log-max SIZE    усекать лог после прочтения SIZE байт (64M); держите лог в tmpfs
  --only-attributed      учитывать только потоки, найденные в логе
  --log-utc-offset ±HH:MM  часовой пояс времени в логе (только analyze, по умолчанию +00:00)
";

struct Opts {
    cfg: Config,
    api: Option<String>,
    webhook: Option<String>,
    exec: Option<String>,
    iface: Option<String>,
    quiet: bool,
    file: Option<String>,
    xray_log: Option<String>,
    utc_offset_s: i64,
    log_max: Option<u64>,
    events_file: Option<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { cfg: Config::default(), api: None, webhook: None, exec: None, iface: None, quiet: false, file: None, xray_log: None, utc_offset_s: 0, log_max: None, events_file: None };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a}: нужно значение"));
        let num = |v: String| v.parse::<u64>().map_err(|_| format!("{a}: не число"));
        match a.as_str() {
            "--threshold" => o.cfg.threshold = num(val()?)? as u32,
            "--window" => o.cfg.window_secs = num(val()?)?,
            "--cooldown" => o.cfg.cooldown_secs = num(val()?)?,
            "--fanout" => o.cfg.fanout_peers = num(val()?)? as usize,
            "--api" => o.api = Some(val()?),
            "--webhook" => o.webhook = Some(val()?),
            "--exec" => o.exec = Some(val()?),
            "--iface" => o.iface = Some(val()?),
            "--quiet" => o.quiet = true,
            "--events-file" => o.events_file = Some(val()?),
            "--xray-log" => o.xray_log = Some(val()?),
            "--xray-log-max" => o.log_max = Some(parse_size(&val()?).ok_or(format!("{a}: например 64M"))?),
            "--only-attributed" => o.cfg.only_attributed = true,
            "--log-utc-offset" => o.utc_offset_s = parse_offset(&val()?).ok_or(format!("{a}: формат ±HH:MM"))?,
            s if !s.starts_with("--") && o.file.is_none() => o.file = Some(s.to_string()),
            s => return Err(format!("неизвестный аргумент: {s}")),
        }
    }
    Ok(o)
}

fn parse_size(v: &str) -> Option<u64> {
    let (n, mul) = match v.as_bytes().last()? {
        b'K' | b'k' => (&v[..v.len() - 1], 1 << 10),
        b'M' | b'm' => (&v[..v.len() - 1], 1 << 20),
        b'G' | b'g' => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    n.parse::<u64>().ok().map(|x| x * mul)
}

fn parse_offset(v: &str) -> Option<i64> {
    let (sign, rest) = match v.as_bytes().first()? {
        b'-' => (-1, &v[1..]),
        b'+' => (1, &v[1..]),
        _ => (1, v),
    };
    let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
    Some(sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60))
}

fn xray_stats(eng: &Engine, idx: &Option<SharedIndex>) -> String {
    match idx {
        None => String::new(),
        Some(i) => {
            let i = i.lock().unwrap();
            format!(
                ",\"xray\":{{\"log_lines\":{},\"ip_lines\":{},\"domain_lines\":{},\"index\":{},\"attributed_flows\":{},\"dropped_lines\":{}}},\"dropped_flows\":{}",
                i.lines, i.matched_lines, i.domain_lines, i.len(), eng.attributed_flows, i.dropped_lines, eng.dropped_flows
            )
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let opts = match parse(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("xtg: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let r = match cmd.as_str() {
        "analyze" => analyze(opts),
        "run" => run(opts),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        _ => Err(format!("неизвестная команда: {cmd}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtg: {e}");
            ExitCode::FAILURE
        }
    }
}

fn sinks(o: &Opts) -> Result<Sinks, String> {
    let mut s = Sinks::new(!o.quiet, o.webhook.clone(), o.exec.clone());
    if let Some(p) = &o.events_file {
        s = s.with_store(p).map_err(|e| format!("{p}: {e}"))?;
    }
    if let Some(addr) = &o.api {
        api::serve(addr, s.state.clone()).map_err(|e| format!("api {addr}: {e}"))?;
        eprintln!("xtg: API на http://{addr}");
    }
    Ok(s)
}

fn analyze(o: Opts) -> Result<(), String> {
    let path = o.file.clone().ok_or("укажите pcap-файл")?;
    let f = File::open(&path).map_err(|e| format!("{path}: {e}"))?;
    let mut rd = PcapReader::new(BufReader::with_capacity(1 << 20, f)).map_err(|e| format!("{path}: {e}"))?;
    let idx = match &o.xray_log {
        Some(p) => {
            let mut i = Index::default();
            xray::load_file(p, o.utc_offset_s, &mut i).map_err(|e| format!("{p}: {e}"))?;
            eprintln!("xtg: xray-лог: строк {}, с IP {}, с доменом {}", i.lines, i.matched_lines, i.domain_lines);
            Some(Arc::new(Mutex::new(i)))
        }
        None => None,
    };
    let sinks = sinks(&o)?;
    let mut eng = Engine::new(o.cfg.clone());
    if let Some(i) = &idx {
        eng = eng.with_xray(i.clone());
    }
    let link = rd.link;
    while let Some((ts, frame)) = rd.next_frame().map_err(|e| e.to_string())? {
        if let Some(p) = packet::parse(link, ts, frame) {
            if let Some(ev) = eng.process(&p) {
                sinks.publish(ev);
            }
        }
    }
    let scores = eng.scores();
    eprintln!("xtg: пакетов {}, субъектов с сигналами {}, потоков с пользователем {}", eng.packets, scores.len(), eng.attributed_flows);
    for s in &scores {
        eprintln!("  {}", score_json(s));
    }
    {
        let mut st = sinks.state.lock().unwrap();
        st.packets = eng.packets;
        st.extra = xray_stats(&eng, &idx);
        st.scores = scores;
    }
    if o.api.is_some() {
        eprintln!("xtg: анализ завершён, API продолжает работать (Ctrl+C для выхода)");
        loop {
            std::thread::park();
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run(o: Opts) -> Result<(), String> {
    use std::time::{Duration, Instant};
    let iface = o.iface.clone().ok_or("укажите --iface")?;
    let mut cap = xray_torrent_guard::live::Capture::open(&iface).map_err(|e| format!("{iface}: {e}"))?;
    let idx: Option<SharedIndex> = o.xray_log.as_ref().map(|p| {
        let i: SharedIndex = Arc::new(Mutex::new(Index::default()));
        xray::follow(p.clone(), i.clone(), xray::FollowOpts { truncate_at: o.log_max });
        eprintln!("xtg: слежу за xray-логом {p}");
        i
    });
    let sinks = sinks(&o)?;
    let mut eng = Engine::new(o.cfg.clone());
    if let Some(i) = &idx {
        eng = eng.with_xray(i.clone());
    }
    eprintln!("xtg: захват на {iface}");
    let mut last = Instant::now();
    let mut reported_drops = 0u64;
    loop {
        let (ts, data) = match cap.next() {
            Ok(v) => v,
            // Интерфейс пропал или упал (перезапуск сети, смена реле): ждём и
            // открываем заново, не теряя состояние движка и события.
            Err(e) => {
                eprintln!("xtg: {iface}: {e} — переоткрываю захват");
                cap = loop {
                    std::thread::sleep(Duration::from_secs(1));
                    if let Ok(c) = xray_torrent_guard::live::Capture::open(&iface) {
                        break c;
                    }
                };
                reported_drops = 0;
                eprintln!("xtg: захват на {iface} восстановлен");
                continue;
            }
        };
        if let Some(p) = packet::parse_ip(ts, data) {
            if let Some(ev) = eng.process(&p) {
                sinks.publish(ev);
            }
        }
        if last.elapsed() > Duration::from_secs(2) {
            last = Instant::now();
            let mut st = sinks.state.lock().unwrap();
            st.packets = eng.packets;
            cap.update_stats();
            if cap.dropped > reported_drops {
                eprintln!("xtg: ядро потеряло {} пакетов (всего {}) — не хватает CPU", cap.dropped - reported_drops, cap.dropped);
                reported_drops = cap.dropped;
            }
            st.extra = format!("{},\"kernel_drops\":{}", xray_stats(&eng, &idx), cap.dropped);
            st.scores = eng.scores();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_o: Opts) -> Result<(), String> {
    Err("живой захват поддерживается только на Linux; используйте `xtg analyze`".into())
}
