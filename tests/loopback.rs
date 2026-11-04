//! End-to-end tests over 127.0.0.1: the responder self-test suite, and the real
//! client loop against the responder.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ntp_nts_diag::client::{self, ClientConfig};
use ntp_nts_diag::report::{Event, Reporter};
use ntp_nts_diag::responder::{FaultMode, Responder};
use ntp_nts_diag::{StopFlag, selftest};

fn capture() -> (Reporter, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let rep = Reporter::new(move |ev| {
        if let Event::Log(l) = ev {
            sink.lock().unwrap().push(l);
        }
    });
    (rep, lines)
}

#[test]
fn responder_self_test_suite_passes() {
    let (rep, lines) = capture();
    let (passed, failed) = selftest::run(&rep);
    assert_eq!(failed, 0, "{:#?}", lines.lock().unwrap());
    assert_eq!(passed, FaultMode::ALL.len());
}

fn client_against(mode: FaultMode, count: u32) -> ntp_nts_diag::stats::ClientStats {
    let (quiet, _) = capture();
    let r = Responder::start(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), mode, quiet).unwrap();
    let cfg = ClientConfig {
        target: format!("127.0.0.1:{}", r.local_addr().port()),
        count,
        delay: Duration::ZERO,
        nts: false,
        udp_timeout: Duration::from_millis(400),
        ..ClientConfig::default()
    };
    let (rep, _) = capture();
    client::run(&cfg, &rep, &StopFlag::new())
}

#[test]
fn client_measures_offset_against_responder() {
    let s = client_against(FaultMode::OffsetPlus100ms, 3);
    assert_eq!((s.sent, s.received, s.failures), (3, 3, 0));
    assert!((s.offset_ms.mean - 100.0).abs() < 50.0, "{:?}", s.offset_ms);
}

#[test]
fn client_counts_failures_and_kod() {
    let s = client_against(FaultMode::BadOriginate, 2);
    assert_eq!((s.received, s.failures), (2, 2));
    let s = client_against(FaultMode::KodDeny, 2);
    assert_eq!((s.kods, s.failures), (2, 0));
    let s = client_against(FaultMode::Drop, 1);
    assert_eq!((s.timeouts, s.received), (1, 0));
}
