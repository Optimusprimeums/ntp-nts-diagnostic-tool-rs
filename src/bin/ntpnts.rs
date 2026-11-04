//! Command-line front end: scriptable queries, responder and self-test.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ntp_nts_diag::client::{self, ClientConfig};
use ntp_nts_diag::report::Reporter;
use ntp_nts_diag::responder::{FaultMode, Responder};
use ntp_nts_diag::{StopFlag, selftest};

#[derive(Parser)]
#[command(
    name = "ntpnts",
    version,
    about = "NTP/NTS Diagnostic Tool (command line)"
)]
struct Cli {
    /// Append every log line to this file.
    #[arg(long, global = true)]
    log: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Query an NTP or NTS server. Exit code 1 if any request failed.
    Query {
        /// host, host:port or [IPv6]:port (NTS-KE port with --nts, NTP port otherwise)
        server: String,
        /// Use NTS (RFC 8915) instead of plain NTP.
        #[arg(long)]
        nts: bool,
        /// Skip TLS certificate verification (lab use only).
        #[arg(long, requires = "nts")]
        insecure: bool,
        /// Number of requests.
        #[arg(short = 'n', long, default_value_t = 5)]
        count: u32,
        /// Delay between requests in milliseconds.
        #[arg(short, long, default_value_t = 1000)]
        delay: u64,
        /// UDP reply timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout: u64,
    },
    /// Run the fault-injecting NTP responder until Ctrl+C.
    Respond {
        #[arg(long, default_value = "0.0.0.0")]
        bind: IpAddr,
        #[arg(long, default_value_t = 123)]
        port: u16,
        /// Fault mode (see `ntpnts modes`).
        #[arg(long, default_value = "valid", value_parser = parse_mode)]
        mode: FaultMode,
    },
    /// Run the loopback responder self-test suite. Exit code 1 on any failure.
    SelfTest,
    /// List responder fault modes.
    Modes,
}

fn parse_mode(s: &str) -> Result<FaultMode, String> {
    FaultMode::from_name(s).ok_or_else(|| {
        format!(
            "unknown mode '{s}'; one of: {}",
            FaultMode::ALL.map(|m| m.name()).join(", ")
        )
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rep = Reporter::stdout();
    if let Err(e) = rep.set_log_file(cli.log.as_deref()) {
        eprintln!("cannot open log file: {e}");
        return ExitCode::from(2);
    }
    match cli.cmd {
        Cmd::Query {
            server,
            nts,
            insecure,
            count,
            delay,
            timeout,
        } => {
            let cfg = ClientConfig {
                target: server,
                count,
                delay: Duration::from_millis(delay),
                nts,
                skip_verify: insecure,
                udp_timeout: Duration::from_millis(timeout),
                ..ClientConfig::default()
            };
            let stats = client::run(&cfg, &rep, &StopFlag::new());
            let ok = stats.sent > 0 && stats.failures == 0 && stats.nts_failures == 0;
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Cmd::Respond { bind, port, mode } => {
            match Responder::start(SocketAddr::new(bind, port), mode, rep.clone()) {
                Ok(_r) => loop {
                    std::thread::park();
                },
                Err(e) => {
                    rep.log(format!("PEER TEST ERROR: {e}"));
                    ExitCode::from(2)
                }
            }
        }
        Cmd::SelfTest => {
            let (_, failed) = selftest::run(&rep);
            if failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Cmd::Modes => {
            for m in FaultMode::ALL {
                println!("{:<20} {}", m.name(), m.description());
            }
            ExitCode::SUCCESS
        }
    }
}
