//! NTP/NTS Diagnostic Tool: NTPv4 and RFC 8915 NTS client diagnostics plus a
//! fault-injecting NTP responder for testing NTP clients and peers.

pub mod client;
pub mod ntp;
pub mod nts;
pub mod report;
pub mod responder;
pub mod selftest;
pub mod stats;
#[cfg(windows)]
pub mod win;

use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const APP_NAME: &str = "NTP/NTS Diagnostic Tool";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A protocol-level validation failure (as opposed to a transport error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl ProtocolError {
    pub fn new(msg: impl Into<String>) -> Self {
        ProtocolError(msg.into())
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolError {}

/// A cancellation flag that can also be waited on, so delays end immediately on stop.
#[derive(Clone, Default)]
pub struct StopFlag(Arc<(Mutex<bool>, Condvar)>);

impl StopFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        *self.0.0.lock().unwrap()
    }

    /// Sleep for up to `d`; returns true if stopped during (or before) the wait.
    pub fn wait(&self, d: Duration) -> bool {
        let guard = self.0.0.lock().unwrap();
        let (guard, _) = self
            .0
            .1
            .wait_timeout_while(guard, d, |stopped| !*stopped)
            .unwrap();
        *guard
    }
}
