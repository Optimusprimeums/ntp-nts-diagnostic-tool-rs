//! Loopback regression suite for the fault-injecting responder.
//!
//! Each check starts the responder in one fault mode on 127.0.0.1, verifies the
//! bytes it put on the wire, and verifies that this tool's own NTP client
//! validation classifies the reply correctly (accept, reject or KoD). It does
//! not claim anything about how an external peer reacts; that peer's logs remain
//! the authority for interoperability behaviour.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::ntp::{self, NtpTimestamp};
use crate::report::{Event, Reporter};
use crate::responder::{FaultMode, Responder};

struct Exchange {
    data: Vec<u8>,
    t1: NtpTimestamp,
    t4: NtpTimestamp,
    elapsed: Duration,
}

impl Exchange {
    fn verdict(&self) -> Result<ntp::NtpResponse, String> {
        ntp::validate_response(&self.data, self.t1, self.t4).map_err(|e| e.to_string())
    }
}

fn exchange(addr: SocketAddr, timeout: Duration) -> io::Result<Exchange> {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    sock.connect(addr)?;
    sock.set_read_timeout(Some(timeout))?;
    let t1 = NtpTimestamp::now();
    let start = Instant::now();
    sock.send(&ntp::build_client_request(t1))?;
    let mut buf = [0u8; 2048];
    let n = sock.recv(&mut buf)?;
    Ok(Exchange {
        data: buf[..n].to_vec(),
        t1,
        t4: NtpTimestamp::now(),
        elapsed: start.elapsed(),
    })
}

fn ensure(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.into()) }
}

fn ex(addr: SocketAddr) -> Result<Exchange, String> {
    exchange(addr, Duration::from_millis(1500)).map_err(|e| format!("no response: {e}"))
}

fn expect_rejected(x: &Exchange, needle: &str) -> Result<String, String> {
    match x.verdict() {
        Err(e) if e.contains(needle) => Ok(format!("client rejected: {e}")),
        Err(e) => Err(format!("client rejected for the wrong reason: {e}")),
        Ok(_) => Err("client accepted a reply it should reject".into()),
    }
}

fn check(mode: FaultMode, addr: SocketAddr) -> Result<String, String> {
    use FaultMode::*;
    match mode {
        Valid => {
            let x = ex(addr)?;
            let d = &x.data;
            ensure(
                d.len() == 48 && d[0] & 7 == 4 && d[1] == 1 && d[24..32] == x.t1.to_bytes(),
                "malformed valid reply",
            )?;
            let r = x.verdict()?;
            let t = r.timing.ok_or("no timing")?;
            ensure(
                t.offset_ms.abs() < 50.0,
                format!("loopback offset {:.3} ms is implausible", t.offset_ms),
            )?;
            Ok(format!(
                "accepted, offset {:+.3} ms, delay {:.3} ms",
                t.offset_ms, t.delay_ms
            ))
        }
        Kod | KodDeny | KodRstr => {
            let code = match mode {
                Kod => "RATE",
                KodDeny => "DENY",
                _ => "RSTR",
            };
            let x = ex(addr)?;
            ensure(
                x.data.len() == 48 && x.data[1] == 0 && &x.data[12..16] == code.as_bytes(),
                "wrong KoD packet",
            )?;
            let r = x.verdict()?;
            ensure(
                r.kiss_code.as_deref() == Some(code),
                "client did not report the kiss code",
            )?;
            Ok(format!("client reported KoD {code}"))
        }
        BadOriginate => {
            let x = ex(addr)?;
            ensure(
                x.data.len() == 48 && x.data[24..32] != x.t1.to_bytes(),
                "originate was echoed",
            )?;
            expect_rejected(&x, "originate")
        }
        Short => {
            let x = ex(addr)?;
            ensure(
                x.data.len() == 16,
                format!("expected 16 bytes, got {}", x.data.len()),
            )?;
            expect_rejected(&x, "short")
        }
        WrongMode => {
            let x = ex(addr)?;
            ensure(x.data.len() == 48 && x.data[0] & 7 == 3, "mode is not 3")?;
            expect_rejected(&x, "mode")
        }
        BadVersion => {
            let x = ex(addr)?;
            ensure(
                x.data.len() == 48 && (x.data[0] >> 3) & 7 == 0,
                "version is not 0",
            )?;
            expect_rejected(&x, "version")
        }
        ZeroT2 | ZeroT3 => {
            let range = if mode == ZeroT2 { 32..40 } else { 40..48 };
            let x = ex(addr)?;
            ensure(
                x.data.len() == 48 && x.data[range].iter().all(|&b| b == 0),
                "timestamp is not zero",
            )?;
            expect_rejected(&x, "zero")
        }
        LiAlarm | Stratum16 => {
            let x = ex(addr)?;
            ensure(x.data.len() == 48, "wrong length")?;
            ensure(mode != LiAlarm || x.data[0] >> 6 == 3, "LI is not 3")?;
            ensure(mode != Stratum16 || x.data[1] == 16, "stratum is not 16")?;
            let r = x.verdict()?;
            let w = r.warnings();
            ensure(
                !w.is_empty(),
                "client accepted without an unsynchronized warning",
            )?;
            Ok(format!("client warned: {}", w.join("; ")))
        }
        Duplicate => {
            let a = ex(addr)?;
            std::thread::sleep(Duration::from_millis(20));
            let b = ex(addr)?;
            ensure(
                a.data.len() == 48 && b.data.len() == 48 && a.data[40..48] == b.data[40..48],
                "T3 differs between replies",
            )?;
            Ok("two requests received identical T3".into())
        }
        Replay => {
            let a = ex(addr)?;
            std::thread::sleep(Duration::from_millis(20));
            let b = ex(addr)?;
            ensure(
                a.data.len() == 48 && a.data == b.data,
                "second reply is not a byte-for-byte replay",
            )?;
            a.verdict()?;
            expect_rejected(&b, "originate").map(|s| format!("replayed packet detected — {s}"))
        }
        Drop => match exchange(addr, Duration::from_millis(350)) {
            Ok(_) => Err("unexpected response".into()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok("request intentionally unanswered".into())
            }
            Err(e) => Err(format!("unexpected error: {e}")),
        },
        Delayed => {
            let x =
                exchange(addr, Duration::from_secs(3)).map_err(|e| format!("no response: {e}"))?;
            let s = x.elapsed.as_secs_f64();
            ensure(
                x.data.len() == 48 && s >= 0.90,
                format!("reply after {s:.3} s"),
            )?;
            x.verdict()?;
            Ok(format!("reply after {s:.3} s"))
        }
        OffsetPlus100ms | OffsetMinus100ms => {
            let expected = if mode == OffsetPlus100ms {
                100.0
            } else {
                -100.0
            };
            let x = ex(addr)?;
            let t = x.verdict()?.timing.ok_or("no timing")?;
            ensure(
                (t.offset_ms - expected).abs() < 75.0,
                format!("client measured offset {:+.1} ms", t.offset_ms),
            )?;
            Ok(format!("client measured offset {:+.1} ms", t.offset_ms))
        }
        Processing100ms => {
            let x = ex(addr)?;
            let t = x.verdict()?.timing.ok_or("no timing")?;
            ensure(
                (85.0..=250.0).contains(&t.server_ms),
                format!("T3-T2={:.1} ms", t.server_ms),
            )?;
            ensure(
                t.delay_ms < 50.0,
                format!(
                    "network delay {:.1} ms should exclude processing time",
                    t.delay_ms
                ),
            )?;
            Ok(format!(
                "T3-T2={:.1} ms, network delay {:.3} ms",
                t.server_ms, t.delay_ms
            ))
        }
    }
}

/// Run every check, logging PASS/FAIL lines. Returns (passed, failed).
pub fn run(reporter: &Reporter) -> (usize, usize) {
    let total = FaultMode::ALL.len();
    reporter.log(format!("=== PEER RESPONDER SELF-TEST: {total} checks ==="));
    let quiet = Reporter::new(|_| {});
    let (mut passed, mut failed) = (0, 0);
    for mode in FaultMode::ALL {
        let outcome = Responder::start(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            mode,
            quiet.clone(),
        )
        .map_err(|e| e.to_string())
        .and_then(|r| {
            let res = check(mode, r.local_addr());
            r.stop();
            res
        });
        match outcome {
            Ok(detail) => {
                passed += 1;
                reporter.log(format!("[PASS] {mode} | {detail}"));
            }
            Err(detail) => {
                failed += 1;
                reporter.log(format!("[FAIL] {mode} | {detail}"));
            }
        }
    }
    reporter.log(format!(
        "=== PEER RESPONDER SELF-TEST COMPLETE: {passed} passed / {failed} failed ==="
    ));
    reporter.emit(Event::SuiteDone { passed, failed });
    (passed, failed)
}
