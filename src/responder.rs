//! Fault-injecting NTP responder used to test how NTP clients and peers react
//! to malformed, hostile or degraded server behaviour.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::StopFlag;
use crate::ntp::NtpTimestamp;
use crate::report::{Event, Reporter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultMode {
    Valid,
    Kod,
    KodDeny,
    KodRstr,
    BadOriginate,
    Short,
    Duplicate,
    WrongMode,
    BadVersion,
    ZeroT2,
    ZeroT3,
    LiAlarm,
    Stratum16,
    Drop,
    Delayed,
    OffsetPlus100ms,
    OffsetMinus100ms,
    Processing100ms,
    Replay,
}

impl FaultMode {
    pub const ALL: [FaultMode; 19] = [
        FaultMode::Valid,
        FaultMode::Kod,
        FaultMode::KodDeny,
        FaultMode::KodRstr,
        FaultMode::BadOriginate,
        FaultMode::Short,
        FaultMode::Duplicate,
        FaultMode::WrongMode,
        FaultMode::BadVersion,
        FaultMode::ZeroT2,
        FaultMode::ZeroT3,
        FaultMode::LiAlarm,
        FaultMode::Stratum16,
        FaultMode::Drop,
        FaultMode::Delayed,
        FaultMode::OffsetPlus100ms,
        FaultMode::OffsetMinus100ms,
        FaultMode::Processing100ms,
        FaultMode::Replay,
    ];

    pub fn name(self) -> &'static str {
        match self {
            FaultMode::Valid => "valid",
            FaultMode::Kod => "kod",
            FaultMode::KodDeny => "kod-deny",
            FaultMode::KodRstr => "kod-rstr",
            FaultMode::BadOriginate => "bad-originate",
            FaultMode::Short => "short",
            FaultMode::Duplicate => "duplicate",
            FaultMode::WrongMode => "wrong-mode",
            FaultMode::BadVersion => "bad-version",
            FaultMode::ZeroT2 => "zero-t2",
            FaultMode::ZeroT3 => "zero-t3",
            FaultMode::LiAlarm => "li-alarm",
            FaultMode::Stratum16 => "stratum-16",
            FaultMode::Drop => "drop",
            FaultMode::Delayed => "delayed",
            FaultMode::OffsetPlus100ms => "offset-plus-100ms",
            FaultMode::OffsetMinus100ms => "offset-minus-100ms",
            FaultMode::Processing100ms => "processing-100ms",
            FaultMode::Replay => "replay",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            FaultMode::Valid => "well-formed stratum-1 reply",
            FaultMode::Kod => "Kiss-o'-Death RATE (stratum 0)",
            FaultMode::KodDeny => "Kiss-o'-Death DENY (stratum 0)",
            FaultMode::KodRstr => "Kiss-o'-Death RSTR (stratum 0)",
            FaultMode::BadOriginate => "originate timestamp does not echo the request",
            FaultMode::Short => "16-byte truncated packet",
            FaultMode::Duplicate => "every reply carries the same transmit timestamp (T3)",
            FaultMode::WrongMode => "reply in client mode 3 instead of server mode 4",
            FaultMode::BadVersion => "version number 0",
            FaultMode::ZeroT2 => "receive timestamp (T2) is zero",
            FaultMode::ZeroT3 => "transmit timestamp (T3) is zero",
            FaultMode::LiAlarm => "leap indicator 3 (unsynchronized)",
            FaultMode::Stratum16 => "stratum 16 (unsynchronized)",
            FaultMode::Drop => "never reply",
            FaultMode::Delayed => "reply after 1 second",
            FaultMode::OffsetPlus100ms => "server clock 100 ms ahead",
            FaultMode::OffsetMinus100ms => "server clock 100 ms behind",
            FaultMode::Processing100ms => "100 ms between T2 and T3",
            FaultMode::Replay => "resend the first reply verbatim to every request",
        }
    }

    pub fn from_name(s: &str) -> Option<FaultMode> {
        let s = s.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|m| m.name() == s)
    }

    fn clock_shift(self) -> f64 {
        match self {
            FaultMode::OffsetPlus100ms => 0.100,
            FaultMode::OffsetMinus100ms => -0.100,
            _ => 0.0,
        }
    }
}

impl std::fmt::Display for FaultMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

pub const DELAYED_REPLY: Duration = Duration::from_secs(1);
pub const PROCESSING_DELAY: Duration = Duration::from_millis(100);

/// Per-responder state that persists across requests.
#[derive(Default)]
struct State {
    duplicate_t3: Option<NtpTimestamp>,
    replay: Option<Vec<u8>>,
}

/// Build the reply for one request, or `None` when the mode drops it.
fn build_reply(mode: FaultMode, request: &[u8], state: &mut State) -> Option<Vec<u8>> {
    match mode {
        FaultMode::Drop => return None,
        FaultMode::Short => {
            let mut r = vec![0u8; 16];
            r[0] = 0x24;
            r[1] = 1;
            return Some(r);
        }
        FaultMode::Replay => {
            if let Some(p) = &state.replay {
                return Some(p.clone());
            }
        }
        _ => {}
    }

    let mut r = vec![0u8; 48];
    r[0] = match mode {
        FaultMode::WrongMode => 0x23,
        FaultMode::BadVersion => 0x04,
        FaultMode::LiAlarm => 0xE4,
        _ => 0x24,
    };
    r[1] = match mode {
        FaultMode::Kod | FaultMode::KodDeny | FaultMode::KodRstr => 0,
        FaultMode::Stratum16 => 16,
        _ => 1,
    };
    r[2] = 6; // poll 64 s
    r[3] = 0xEC; // precision 2^-20
    r[8..12].copy_from_slice(&1u32.to_be_bytes()); // root dispersion ~15 µs
    r[12..16].copy_from_slice(match mode {
        FaultMode::Kod => b"RATE",
        FaultMode::KodDeny => b"DENY",
        FaultMode::KodRstr => b"RSTR",
        _ => b"TEST",
    });

    let shift = mode.clock_shift();
    let t2 = NtpTimestamp::now().add_secs(shift);
    r[16..24].copy_from_slice(&t2.add_secs(-1.0).to_bytes());
    if mode == FaultMode::BadOriginate {
        r[24..32].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_be_bytes());
    } else {
        r[24..32].copy_from_slice(&request[40..48]);
    }
    if mode != FaultMode::ZeroT2 {
        r[32..40].copy_from_slice(&t2.to_bytes());
    }
    if mode == FaultMode::Processing100ms {
        thread::sleep(PROCESSING_DELAY);
    }
    let t3 = match mode {
        FaultMode::Duplicate => *state.duplicate_t3.get_or_insert_with(NtpTimestamp::now),
        _ => NtpTimestamp::now().add_secs(shift),
    };
    if mode != FaultMode::ZeroT3 {
        r[40..48].copy_from_slice(&t3.to_bytes());
    }
    if mode == FaultMode::Replay {
        state.replay = Some(r.clone());
    }
    Some(r)
}

pub struct Responder {
    stop: StopFlag,
    thread: Option<JoinHandle<()>>,
    local_addr: SocketAddr,
}

impl Responder {
    /// Bind synchronously (so errors surface immediately) and serve on a background thread.
    pub fn start(bind: SocketAddr, mode: FaultMode, reporter: Reporter) -> io::Result<Responder> {
        let sock = UdpSocket::bind(bind).map_err(|e| bind_error(bind, e))?;
        sock.set_read_timeout(Some(Duration::from_millis(200)))?;
        let local_addr = sock.local_addr()?;
        let stop = StopFlag::new();
        reporter.log(format!(
            "NTP peer test responder listening on {local_addr}/UDP | mode={mode} ({})",
            mode.description()
        ));
        let thread_stop = stop.clone();
        let thread = thread::Builder::new()
            .name(format!("responder-{mode}"))
            .spawn(move || serve(sock, mode, thread_stop, reporter))?;
        Ok(Responder {
            stop,
            thread: Some(thread),
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.stop();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn bind_error(bind: SocketAddr, e: io::Error) -> io::Error {
    let hint = match e.kind() {
        io::ErrorKind::AddrInUse if bind.port() == 123 => {
            " — another NTP service already owns UDP/123 (on Windows this is usually W32Time: `net stop w32time`), or choose another port"
        }
        io::ErrorKind::AddrInUse => " — the port is already in use",
        io::ErrorKind::PermissionDenied => {
            " — try running as Administrator or choose an unprivileged port"
        }
        io::ErrorKind::AddrNotAvailable => " — that address is not assigned to this machine",
        _ => "",
    };
    io::Error::new(e.kind(), format!("cannot bind {bind}/UDP: {e}{hint}"))
}

fn serve(sock: UdpSocket, mode: FaultMode, stop: StopFlag, reporter: Reporter) {
    let mut state = State::default();
    let mut buf = [0u8; 2048];
    while !stop.is_stopped() {
        let (len, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            // Windows reports an ICMP port-unreachable from an earlier send as a
            // reset on the next receive; it is not a responder failure.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => {
                reporter.log(format!("PEER TEST ERROR: {e}"));
                break;
            }
        };
        let request = &buf[..len];
        if len < 48 {
            reporter.log(format!(
                "PEER TEST {peer}: ignored short request ({len} bytes)"
            ));
            continue;
        }
        let req_mode = request[0] & 7;
        reporter.log(format!(
            "PEER TEST {peer}: request {len} bytes (VN={} mode={req_mode}) | fault={mode}",
            (request[0] >> 3) & 7
        ));

        let Some(reply) = build_reply(mode, request, &mut state) else {
            reporter.log("PEER TEST -> request intentionally dropped");
            continue;
        };
        let summary = if reply.len() >= 48 {
            format!(
                "{} bytes | stratum={} | refid={}",
                reply.len(),
                reply[1],
                String::from_utf8_lossy(&reply[12..16])
            )
        } else {
            format!("{}-byte malformed packet", reply.len())
        };

        if mode == FaultMode::Delayed {
            let Ok(s) = sock.try_clone() else { continue };
            let r = reporter.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                if !stop.wait(DELAYED_REPLY) {
                    let _ = s.send_to(&reply, peer);
                    r.log(format!(
                        "PEER TEST -> sent delayed response after {} ms | {summary}",
                        DELAYED_REPLY.as_millis()
                    ));
                }
            });
            continue;
        }
        match sock.send_to(&reply, peer) {
            Ok(_) => reporter.log(format!("PEER TEST -> sent response | {summary}")),
            Err(e) => reporter.log(format!("PEER TEST ERROR sending to {peer}: {e}")),
        }
    }
    reporter.log("NTP peer test responder stopped.");
    reporter.emit(Event::ResponderStopped);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_roundtrip() {
        for m in FaultMode::ALL {
            assert_eq!(FaultMode::from_name(m.name()), Some(m));
        }
        assert_eq!(FaultMode::from_name("nope"), None);
    }

    #[test]
    fn replies_are_well_sized() {
        let req = crate::ntp::build_client_request(NtpTimestamp::now());
        for m in FaultMode::ALL {
            if m == FaultMode::Processing100ms {
                continue;
            }
            let mut st = State::default();
            match build_reply(m, &req, &mut st) {
                None => assert_eq!(m, FaultMode::Drop),
                Some(r) if m == FaultMode::Short => assert_eq!(r.len(), 16),
                Some(r) => assert_eq!(r.len(), 48, "{m}"),
            }
        }
    }
}
