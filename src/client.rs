//! The request loop shared by the GUI and the command-line tool.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::ntp::{self, DEFAULT_NTP_PORT, NtpResponse, NtpTimestamp};
use crate::nts::{self, NTS_KE_PORT, NtsSession};
use crate::report::{Event, Reporter};
use crate::stats::ClientStats;
use crate::{APP_NAME, APP_VERSION, ProtocolError, StopFlag};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// `host`, `host:port` or `[v6]:port`. The port is the NTS-KE port when NTS is
    /// enabled (default 4460) and the NTP port otherwise (default 123).
    pub target: String,
    pub count: u32,
    pub delay: Duration,
    pub nts: bool,
    pub skip_verify: bool,
    pub ke_timeout: Duration,
    pub udp_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            target: "time.cloudflare.com".into(),
            count: 5,
            delay: Duration::from_millis(1000),
            nts: true,
            skip_verify: false,
            ke_timeout: Duration::from_secs(5),
            udp_timeout: Duration::from_secs(3),
        }
    }
}

enum Failure {
    Timeout,
    Io(io::Error),
    Protocol(ProtocolError),
}

impl From<ProtocolError> for Failure {
    fn from(e: ProtocolError) -> Self {
        Failure::Protocol(e)
    }
}

fn resolve(host: &str, port: u16) -> io::Result<SocketAddr> {
    (host.trim_end_matches('.'), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "name resolution returned no addresses",
            )
        })
}

/// Send one datagram on a connected socket (so only the target's replies are
/// accepted) and wait for the reply.
fn udp_exchange(
    addr: SocketAddr,
    packet: &[u8],
    timeout: Duration,
) -> Result<(Vec<u8>, NtpTimestamp, NtpTimestamp), Failure> {
    let local: IpAddr = if addr.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    let sock = UdpSocket::bind((local, 0)).map_err(Failure::Io)?;
    sock.connect(addr).map_err(Failure::Io)?;
    sock.set_read_timeout(Some(timeout)).map_err(Failure::Io)?;
    let mut buf = vec![0u8; 65535];
    // T1 is taken as late as possible; the packet already contains it.
    let t1 = NtpTimestamp::from_bytes(&packet[40..48]);
    sock.send(packet).map_err(Failure::Io)?;
    match sock.recv(&mut buf) {
        Ok(n) => {
            let t4 = NtpTimestamp::now();
            buf.truncate(n);
            Ok((buf, t1, t4))
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(Failure::Timeout)
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Err(Failure::Io(io::Error::new(
            e.kind(),
            "ICMP port unreachable: nothing is listening on that UDP port",
        ))),
        Err(e) => Err(Failure::Io(e)),
    }
}

fn do_ke(
    cfg: &ClientConfig,
    host: &str,
    port: u16,
    stats: &mut ClientStats,
    rep: &Reporter,
) -> Option<NtsSession> {
    stats.ke_exchanges += 1;
    match nts::perform_ke(host, port, cfg.skip_verify, cfg.ke_timeout) {
        Ok(s) => {
            rep.log(format!(
                "NTS-KE SUCCESS: {}, {}, ALPN=ntske/1, AEAD={} (AEAD_AES_SIV_CMAC_256)",
                s.tls_version, s.cipher, s.aead_id
            ));
            rep.log(format!(
                "NTS-KE: received {} cookie(s) of {} bytes; NTP endpoint={}:{}",
                s.cookies.len(),
                s.cookies[0].len(),
                s.ntp_host,
                s.ntp_port
            ));
            for w in &s.warnings {
                rep.log(format!("NTS-KE WARNING record from server: code {w}"));
            }
            rep.log("NTS-KE: C2S/S2C keys derived with the TLS exporter (key bytes are intentionally not logged).");
            Some(s)
        }
        Err(e) => {
            stats.nts_failures += 1;
            rep.log(format!("NTS-KE FAILED: {e}"));
            None
        }
    }
}

fn log_ntp(rep: &Reporter, r: &NtpResponse) {
    rep.log(format!("NTP: {r}"));
    for w in r.warnings() {
        rep.log(format!("WARNING: {w}"));
    }
}

/// Run `cfg.count` requests, reporting progress. Returns the final statistics.
pub fn run(cfg: &ClientConfig, rep: &Reporter, stop: &StopFlag) -> ClientStats {
    let mut stats = ClientStats::default();
    let result = run_inner(cfg, rep, stop, &mut stats);
    if let Err(e) = result {
        rep.log(format!("ERROR: {e}"));
    }
    if stats.sent > 0 {
        rep.log(format!(
            "SUMMARY: sent {} | received {} | loss {:.1}% | failures {} (timeouts {}) | NTS failures {} | KoD {} | authenticated {} | NTS-KE exchanges {}",
            stats.sent,
            stats.received,
            stats.loss_percent(),
            stats.failures,
            stats.timeouts,
            stats.nts_failures,
            stats.kods,
            stats.authenticated,
            stats.ke_exchanges
        ));
        rep.log(format!("SUMMARY offset: {}", stats.offset_ms.summary("ms")));
        rep.log(format!("SUMMARY delay:  {}", stats.delay_ms.summary("ms")));
    }
    rep.log("Execution complete.");
    rep.emit(Event::Stats(stats));
    rep.emit(Event::ClientDone);
    stats
}

fn run_inner(
    cfg: &ClientConfig,
    rep: &Reporter,
    stop: &StopFlag,
    stats: &mut ClientStats,
) -> Result<(), ProtocolError> {
    let default_port = if cfg.nts {
        NTS_KE_PORT
    } else {
        DEFAULT_NTP_PORT
    };
    let (host, port) = nts::split_host_port(&cfg.target, default_port)?;
    rep.log(format!(
        "Starting {APP_NAME} {APP_VERSION} against {host}:{port} | Count={} | Delay={} ms | NTS={}",
        cfg.count,
        cfg.delay.as_millis(),
        if cfg.nts { "ON" } else { "OFF" }
    ));

    let mut session = None;
    if cfg.nts {
        rep.log(format!(
            "NTS-KE: connecting to {host}:{port}; TLS certificate verification={}",
            if cfg.skip_verify {
                "OFF (insecure)"
            } else {
                "ON"
            }
        ));
        session = do_ke(cfg, &host, port, stats, rep);
        rep.emit(Event::Stats(*stats));
        if session.is_none() {
            return Ok(());
        }
    }

    for i in 1..=cfg.count {
        if stop.is_stopped() {
            rep.log("Execution aborted by user.");
            break;
        }
        rep.log(format!("--- Request {i}/{} ---", cfg.count));

        if let Some(s) = &session
            && s.cookies.is_empty()
        {
            rep.log("NTS cookie pool exhausted; performing a fresh NTS-KE exchange.");
            session = do_ke(cfg, &host, port, stats, rep);
            if session.is_none() {
                break;
            }
        }

        let outcome = one_request(cfg, &host, port, session.as_mut(), stats, rep);
        match outcome {
            Ok(()) => {}
            Err(Failure::Timeout) => {
                stats.failures += 1;
                stats.timeouts += 1;
                rep.log(format!(
                    "ERROR: UDP request timed out after {} ms.",
                    cfg.udp_timeout.as_millis()
                ));
            }
            Err(Failure::Io(e)) => {
                stats.failures += 1;
                rep.log(format!("ERROR: {e}"));
            }
            Err(Failure::Protocol(e)) => {
                stats.failures += 1;
                if cfg.nts {
                    stats.nts_failures += 1;
                }
                rep.log(format!("ERROR: {e}"));
            }
        }
        rep.emit(Event::Stats(*stats));

        if i < cfg.count && !cfg.delay.is_zero() && stop.wait(cfg.delay) {
            rep.log("Execution aborted by user.");
            break;
        }
    }
    Ok(())
}

fn one_request(
    cfg: &ClientConfig,
    host: &str,
    port: u16,
    session: Option<&mut NtsSession>,
    stats: &mut ClientStats,
    rep: &Reporter,
) -> Result<(), Failure> {
    match session {
        Some(s) => {
            let addr = resolve(&s.ntp_host, s.ntp_port).map_err(Failure::Io)?;
            let req = nts::build_request(s, NtpTimestamp::now())?;
            rep.log(format!(
                "Sending NTS request to {}:{} ({addr}): {} bytes, UID 32 bytes, {} cookie placeholder(s), AEAD_AES_SIV_CMAC_256",
                s.ntp_host,
                s.ntp_port,
                req.packet.len(),
                req.placeholders
            ));
            stats.sent += 1;
            rep.emit(Event::Stats(*stats));
            let (data, _t1, t4) = udp_exchange(addr, &req.packet, cfg.udp_timeout)?;
            stats.received += 1;
            rep.log(format!("Received {} bytes from {addr}", data.len()));
            let r = nts::validate_response(&data, s, &req, t4)?;
            log_ntp(rep, &r.ntp);
            if let Some(code) = &r.ntp.kiss_code {
                stats.kods += 1;
                let auth = if r.authenticated {
                    "authenticated"
                } else {
                    "unauthenticated"
                };
                rep.log(format!("WARNING: Kiss-o'-Death {code} ({auth})"));
                if code == "NTSN" {
                    stats.nts_failures += 1;
                    rep.log("NTSN: server could not decrypt the cookie; discarding the cookie pool and repeating NTS-KE.");
                    s.cookies.clear();
                }
                return Ok(());
            }
            record_timing(&r.ntp, stats, rep);
            stats.authenticated += 1;
            rep.log(format!(
                "NTS AUTHENTICATED: UID matched, S2C tag verified, new cookies={}, pool={}",
                r.new_cookies,
                s.cookies.len()
            ));
        }
        None => {
            let addr = resolve(host, port).map_err(Failure::Io)?;
            let packet = ntp::build_client_request(NtpTimestamp::now());
            rep.log(format!("Sending NTP request to {host}:{port} ({addr})"));
            stats.sent += 1;
            rep.emit(Event::Stats(*stats));
            let (data, t1, t4) = udp_exchange(addr, &packet, cfg.udp_timeout)?;
            stats.received += 1;
            rep.log(format!("Received {} bytes from {addr}", data.len()));
            let r = ntp::validate_response(&data, t1, t4)?;
            log_ntp(rep, &r);
            if let Some(code) = &r.kiss_code {
                stats.kods += 1;
                rep.log(format!("WARNING: Kiss-o'-Death packet: {code}"));
                return Ok(());
            }
            record_timing(&r, stats, rep);
        }
    }
    Ok(())
}

fn record_timing(r: &NtpResponse, stats: &mut ClientStats, rep: &Reporter) {
    if let Some(t) = r.timing {
        stats.offset_ms.push(t.offset_ms);
        stats.delay_ms.push(t.delay_ms);
        rep.log(format!(
            "Timing: offset={:+.3} ms | network delay={:.3} ms | server processing={:.3} ms",
            t.offset_ms, t.delay_ms, t.server_ms
        ));
    }
}
