//! egui front end.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, Button, Color32, FontId, Key, Layout, Margin, ProgressBar, RichText,
    Sense, Shape, Stroke, ThemePreference, pos2, vec2,
};
use serde::{Deserialize, Serialize};

use crate::theme::{
    self, ACCENT, ACCENT_HOVER, BUTTON, DANGER, Palette, SUCCESS, VIOLET, WARNING, icon,
};
use ntp_nts_diag::client::{self, ClientConfig};
use ntp_nts_diag::report::{Event, Reporter};
use ntp_nts_diag::responder::{FaultMode, Responder};
use ntp_nts_diag::stats::ClientStats;
use ntp_nts_diag::{APP_NAME, APP_VERSION, StopFlag, selftest};

const MAX_LOG_LINES: usize = 200_000;
const MAX_HISTORY: usize = 600;
const SIDEBAR_WIDTH: f32 = 372.0;
/// Set to a `.png` path to run an unattended demo and save a screenshot of it (used for the docs).
const CAPTURE_ENV: &str = "NTPNTS_SCREENSHOT";

/// State of an unattended screenshot run.
struct Capture {
    path: PathBuf,
    idle_since: Option<Instant>,
    requested: bool,
}

/// Settings for a screenshot run; nothing the user saved is used or overwritten.
fn capture_settings() -> Settings {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    Settings {
        target: env("NTPNTS_SCREENSHOT_TARGET").unwrap_or_else(|| "time.cloudflare.com".into()),
        count: 30,
        delay_ms: 1000,
        nts: true,
        bind: "127.0.0.1".into(),
        port: 12300,
        theme: match env("NTPNTS_SCREENSHOT_THEME").as_deref() {
            Some("light") => ThemeChoice::Light,
            _ => ThemeChoice::Dark,
        },
        startup_prompts: false,
        ..Settings::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
}

impl From<ThemeChoice> for ThemePreference {
    fn from(t: ThemeChoice) -> Self {
        match t {
            ThemeChoice::System => ThemePreference::System,
            ThemeChoice::Light => ThemePreference::Light,
            ThemeChoice::Dark => ThemePreference::Dark,
        }
    }
}

/// A modal dialog: the launch prompts carried over from 2.x, or an action's result.
#[cfg(windows)]
#[derive(Clone)]
enum Dialog {
    Elevate,
    Firewall,
    Result {
        title: String,
        body: String,
        ok: bool,
    },
}

/// Everything remembered between launches.
#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct Settings {
    target: String,
    count: u32,
    delay_ms: u32,
    nts: bool,
    skip_verify: bool,
    log_to_file: bool,
    log_path: Option<PathBuf>,
    bind: String,
    port: u16,
    mode: String,
    theme: ThemeChoice,
    /// Ask about elevation / the firewall rule at launch, as 2.x did.
    startup_prompts: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let d = ClientConfig::default();
        Settings {
            target: d.target,
            count: d.count,
            delay_ms: d.delay.as_millis() as u32,
            nts: d.nts,
            skip_verify: d.skip_verify,
            log_to_file: false,
            log_path: None,
            bind: "0.0.0.0".into(),
            port: 123,
            mode: FaultMode::Valid.name().into(),
            theme: ThemeChoice::System,
            startup_prompts: true,
        }
    }
}

pub struct App {
    rx: Receiver<Event>,
    reporter: Reporter,
    s: Settings,
    mode: FaultMode,
    icons: bool,
    is_admin: bool,

    client_stop: Option<StopFlag>,
    run_count: u32,
    stats: ClientStats,
    /// (offset ms, delay ms) per timed reply in the current run.
    history: Vec<(f64, f64)>,

    responder: Option<Responder>,
    suite_running: bool,
    suite_result: Option<(usize, usize)>,

    log: Vec<String>,
    filter: String,

    #[cfg(windows)]
    dialog: Option<Dialog>,
    #[cfg(windows)]
    fw_rule: Result<Option<ntp_nts_diag::win::FirewallRule>, String>,
    #[cfg(windows)]
    w32time: Option<bool>,

    capture: Option<Capture>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let ctx = &cc.egui_ctx;
        let icons = theme::install_fonts(ctx);
        theme::install_style(ctx);
        let s: Settings = cc
            .storage
            .and_then(|st| eframe::get_value(st, eframe::APP_KEY))
            .unwrap_or_default();
        let capture = std::env::var_os(CAPTURE_ENV).map(|p| Capture {
            path: p.into(),
            idle_since: None,
            requested: false,
        });
        let s = if capture.is_some() {
            capture_settings()
        } else {
            s
        };
        ctx.set_theme(s.theme);

        let (tx, rx) = channel();
        let repaint = ctx.clone();
        let reporter = Reporter::new(move |ev| {
            let _ = tx.send(ev);
            repaint.request_repaint();
        });
        #[cfg(windows)]
        let is_admin = ntp_nts_diag::win::is_admin();
        #[cfg(not(windows))]
        let is_admin = false;

        let mut app = App {
            rx,
            reporter,
            mode: FaultMode::from_name(&s.mode).unwrap_or(FaultMode::Valid),
            s,
            icons,
            is_admin,
            client_stop: None,
            run_count: 0,
            stats: ClientStats::default(),
            history: Vec::new(),
            responder: None,
            suite_running: false,
            suite_result: None,
            log: Vec::new(),
            filter: String::new(),
            #[cfg(windows)]
            dialog: None,
            #[cfg(windows)]
            fw_rule: Ok(None),
            #[cfg(windows)]
            w32time: None,
            capture,
        };
        app.apply_log_file();
        #[cfg(windows)]
        {
            app.reporter.log(format!(
                "Windows privilege status: Administrator={}",
                if is_admin { "YES" } else { "NO" }
            ));
            app.refresh_windows_state();
            if app.s.startup_prompts {
                let rule_ok = matches!(&app.fw_rule, Ok(Some(r)) if r.allows_port(app.s.port));
                app.dialog = match (is_admin, rule_ok) {
                    (false, _) => Some(Dialog::Elevate),
                    (true, false) => Some(Dialog::Firewall),
                    (true, true) => None,
                };
            }
        }
        if app.capture.is_some() {
            app.start_responder();
            app.start_client();
        }
        app
    }

    /// Drive a screenshot run: wait for the client to finish, capture, save, close.
    fn capture_tick(&mut self, ctx: &egui::Context) {
        let running = self.running();
        let Some(c) = &mut self.capture else {
            return;
        };
        ctx.request_repaint_after(Duration::from_millis(100));
        if c.requested {
            return;
        }
        if running {
            c.idle_since = None;
            return;
        }
        if c.idle_since.get_or_insert_with(Instant::now).elapsed() > Duration::from_millis(1500) {
            let (path, ctx2) = (c.path.clone(), ctx.clone());
            ctx.request_screenshot(move |image| {
                match save_png(&path, &image) {
                    Ok(()) => eprintln!("saved {}", path.display()),
                    Err(e) => eprintln!("screenshot failed: {e}"),
                }
                ctx2.send_viewport_cmd(egui::ViewportCommand::Close);
                ctx2.request_repaint();
            });
            c.requested = true;
        }
    }

    /// Prefix `label` with an icon glyph when the icon font is available.
    fn ic(&self, glyph: char, label: &str) -> String {
        match (self.icons, label.is_empty()) {
            (true, true) => glyph.to_string(),
            (true, false) => format!("{glyph}  {label}"),
            (false, _) => label.to_string(),
        }
    }

    // --- state -----------------------------------------------------------

    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Log(line) => {
                    self.log.push(line);
                    if self.log.len() > MAX_LOG_LINES {
                        self.log.drain(..MAX_LOG_LINES / 10);
                    }
                }
                Event::Stats(s) => {
                    if s.offset_ms.n > self.stats.offset_ms.n {
                        self.history.push((s.offset_ms.last, s.delay_ms.last));
                        if self.history.len() > MAX_HISTORY {
                            self.history.remove(0);
                        }
                    }
                    self.stats = s;
                }
                Event::ClientDone => self.client_stop = None,
                Event::SuiteDone { passed, failed } => {
                    self.suite_running = false;
                    self.suite_result = Some((passed, failed));
                }
                Event::ResponderStopped => {}
            }
        }
        if self.responder.as_ref().is_some_and(Responder::is_finished) {
            self.responder = None;
        }
    }

    fn running(&self) -> bool {
        self.client_stop.is_some()
    }

    fn start_client(&mut self) {
        if self.running() {
            return;
        }
        if self.s.log_to_file && self.s.log_path.is_none() {
            self.reporter
                .log("ERROR: Log to file is on but no file is selected.");
            return;
        }
        if self.s.target.trim().is_empty() {
            self.reporter.log("ERROR: Server is empty.");
            return;
        }
        self.log.clear();
        self.stats = ClientStats::default();
        self.history.clear();
        self.run_count = self.s.count;
        let cfg = ClientConfig {
            target: self.s.target.trim().to_string(),
            count: self.s.count,
            delay: Duration::from_millis(self.s.delay_ms as u64),
            nts: self.s.nts,
            skip_verify: self.s.nts && self.s.skip_verify,
            ..ClientConfig::default()
        };
        let stop = StopFlag::new();
        self.client_stop = Some(stop.clone());
        let rep = self.reporter.clone();
        thread::spawn(move || client::run(&cfg, &rep, &stop));
    }

    fn stop_client(&mut self) {
        if let Some(s) = &self.client_stop
            && !s.is_stopped()
        {
            s.stop();
            self.reporter
                .log("Stop requested; waiting for the active network operation to finish…");
        }
    }

    fn start_responder(&mut self) {
        let ip: IpAddr = match self.s.bind.trim().parse() {
            Ok(ip) => ip,
            Err(_) => {
                self.reporter.log(format!(
                    "PEER TEST ERROR: '{}' is not an IPv4/IPv6 address.",
                    self.s.bind.trim()
                ));
                return;
            }
        };
        match Responder::start(
            SocketAddr::new(ip, self.s.port),
            self.mode,
            self.reporter.clone(),
        ) {
            Ok(r) => self.responder = Some(r),
            Err(e) => self.reporter.log(format!("PEER TEST ERROR: {e}")),
        }
    }

    fn start_suite(&mut self) {
        self.suite_running = true;
        self.suite_result = None;
        let rep = self.reporter.clone();
        thread::spawn(move || selftest::run(&rep));
    }

    fn apply_log_file(&mut self) {
        let path = if self.s.log_to_file {
            self.s.log_path.as_deref()
        } else {
            None
        };
        if let Err(e) = self.reporter.set_log_file(path) {
            self.reporter
                .log(format!("ERROR: cannot open log file: {e}"));
        }
    }

    fn visible_lines(&self) -> Vec<&str> {
        let f = self.filter.trim().to_lowercase();
        self.log
            .iter()
            .map(String::as_str)
            .filter(|l| f.is_empty() || l.to_lowercase().contains(&f))
            .collect()
    }

    // --- header and status bar -------------------------------------------

    fn header(&mut self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        ui.horizontal(|ui| {
            if self.icons {
                ui.label(RichText::new(icon::CLOCK).size(22.0).color(ACCENT));
            }
            ui.label(RichText::new("NTP/NTS Diagnostic Tool").font(theme::bold(18.0)));
            ui.label(RichText::new(format!("v{APP_VERSION}")).color(p.muted));
            ui.add_space(12.0);

            let (txt, col) = match &self.client_stop {
                Some(_) => (
                    format!("Client running · {}/{}", self.stats.sent, self.run_count),
                    ACCENT,
                ),
                None => ("Client idle".to_string(), p.muted),
            };
            pill(ui, &txt, col);
            match &self.responder {
                Some(r) => pill(
                    ui,
                    &format!("Responder on {} · {}", r.local_addr(), self.mode),
                    SUCCESS,
                ),
                None => pill(ui, "Responder off", p.muted),
            }
            if self.suite_running {
                pill(ui, "Self-test running", ACCENT);
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                for (choice, glyph, name) in [
                    (ThemeChoice::Dark, icon::MOON, "Dark"),
                    (ThemeChoice::Light, icon::SUN, "Light"),
                    (ThemeChoice::System, icon::SYSTEM, "System"),
                ] {
                    let label = if self.icons {
                        glyph.to_string()
                    } else {
                        name.to_string()
                    };
                    if ui
                        .selectable_label(self.s.theme == choice, label)
                        .on_hover_text(format!("{name} theme"))
                        .clicked()
                    {
                        self.s.theme = choice;
                        ui.ctx().set_theme(choice);
                    }
                }
                ui.label(RichText::new("Theme").color(p.muted));
            });
        });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        ui.horizontal(|ui| {
            let small = |t: String| RichText::new(t).size(12.0).color(p.muted);
            let file = match (&self.s.log_to_file, &self.s.log_path) {
                (true, Some(path)) => format!("Logging to {}", path.display()),
                _ => "Not logging to a file".into(),
            };
            ui.label(small(file));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(small(format!("{} log lines", self.log.len())));
                ui.label(small("Ctrl+Enter start  ·  Esc stop  ·".into()));
                #[cfg(windows)]
                ui.label(small(format!(
                    "{}  ·",
                    if self.is_admin {
                        "Administrator"
                    } else {
                        "Standard user"
                    }
                )));
            });
        });
    }

    // --- sidebar ---------------------------------------------------------

    fn client_card(&mut self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        let running = self.running();
        p.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            card_title(
                ui,
                &self.ic(icon::NETWORK, ""),
                "Client",
                "Query an NTP or NTS server",
            );

            field_label(ui, "Server");
            ui.add_enabled(
                !running,
                egui::TextEdit::singleline(&mut self.s.target)
                    .hint_text("host, host:port or [IPv6]:port")
                    .desired_width(f32::INFINITY)
                    .margin(vec2(8.0, 6.0)),
            )
            .on_hover_text(
                "With NTS the port is the NTS-KE port (default 4460); \
                 without NTS it is the NTP port (default 123).",
            );

            ui.columns(2, |cols| {
                field_label(&mut cols[0], "Requests");
                cols[0].add_enabled(
                    !running,
                    egui::DragValue::new(&mut self.s.count).range(1..=100_000),
                );
                field_label(&mut cols[1], "Delay");
                cols[1].add_enabled(
                    !running,
                    egui::DragValue::new(&mut self.s.delay_ms)
                        .range(0..=600_000)
                        .speed(10)
                        .suffix(" ms"),
                );
            });

            ui.add_space(2.0);
            ui.add_enabled(
                !running,
                egui::Checkbox::new(&mut self.s.nts, "Use NTS (RFC 8915, TCP 4460)"),
            );
            ui.add_enabled_ui(!running && self.s.nts, |ui| {
                let label = if self.s.skip_verify {
                    RichText::new("Skip TLS certificate verification").color(WARNING)
                } else {
                    RichText::new("Skip TLS certificate verification")
                };
                ui.checkbox(&mut self.s.skip_verify, label)
                    .on_hover_text("Lab use only: accepts any certificate.");
            });

            ui.horizontal(|ui| {
                if ui
                    .checkbox(&mut self.s.log_to_file, "Log to file")
                    .changed()
                {
                    self.apply_log_file();
                }
                if ui
                    .add_enabled(
                        self.s.log_to_file,
                        Button::new(self.ic(icon::FOLDER, "Choose…")).small(),
                    )
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter("Log files", &["log", "txt"])
                        .set_file_name("ntp-nts-diagnostic.log")
                        .save_file()
                {
                    self.s.log_path = Some(path);
                    self.apply_log_file();
                }
            });
            if self.s.log_to_file {
                let name = self
                    .s
                    .log_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "No file selected".into());
                ui.label(RichText::new(name).size(12.0).color(p.muted));
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 8.0) / 2.0;
                if primary_button(ui, &self.ic(icon::PLAY, "Start"), !running, w).clicked() {
                    self.start_client();
                }
                let stop = Button::new(self.ic(icon::STOP, "Stop")).min_size(vec2(w, 34.0));
                let stopping = self.client_stop.as_ref().is_some_and(StopFlag::is_stopped);
                if ui.add_enabled(running && !stopping, stop).clicked() {
                    self.stop_client();
                }
            });
            if running {
                let frac = self.stats.sent as f32 / self.run_count.max(1) as f32;
                ui.add(
                    ProgressBar::new(frac)
                        .desired_height(6.0)
                        .fill(ACCENT)
                        .corner_radius(3.0),
                );
            }
        });
    }

    fn responder_card(&mut self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        let active = self.responder.is_some();
        p.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            card_title(
                ui,
                &self.ic(icon::DIAGNOSTIC, ""),
                "Peer test responder",
                "Fault-injecting NTP server",
            );
            ui.columns(2, |cols| {
                field_label(&mut cols[0], "Bind address");
                cols[0].add_enabled(
                    !active,
                    egui::TextEdit::singleline(&mut self.s.bind)
                        .desired_width(f32::INFINITY)
                        .margin(vec2(8.0, 6.0)),
                );
                field_label(&mut cols[1], "UDP port");
                cols[1].add_enabled(
                    !active,
                    egui::DragValue::new(&mut self.s.port).range(1..=65535),
                );
            });

            field_label(ui, "Response mode");
            ui.add_enabled_ui(!active, |ui| {
                egui::ComboBox::from_id_salt("mode")
                    .selected_text(self.mode.name())
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for m in FaultMode::ALL {
                            ui.selectable_value(&mut self.mode, m, m.name())
                                .on_hover_text(m.description());
                        }
                    });
            });
            ui.label(
                RichText::new(self.mode.description())
                    .size(12.0)
                    .color(p.muted),
            );

            ui.horizontal(|ui| {
                let w = (ui.available_width() - 8.0) / 2.0;
                if primary_button(ui, &self.ic(icon::PLAY, "Start"), !active, w).clicked() {
                    self.start_responder();
                }
                let stop = Button::new(self.ic(icon::STOP, "Stop")).min_size(vec2(w, 34.0));
                if ui.add_enabled(active, stop).clicked()
                    && let Some(r) = self.responder.take()
                {
                    self.reporter.log("NTP peer test responder stop requested.");
                    r.stop();
                }
            });
            ui.horizontal(|ui| {
                let b = Button::new(self.ic(icon::CHECK, "Run self-test suite"));
                if ui
                    .add_enabled(!self.suite_running, b)
                    .on_hover_text("Checks every fault mode over 127.0.0.1")
                    .clicked()
                {
                    self.start_suite();
                }
                if self.suite_running {
                    ui.spinner();
                } else if let Some((pass, fail)) = self.suite_result {
                    let (t, c) = if fail == 0 {
                        (format!("{pass}/{} passed", pass + fail), SUCCESS)
                    } else {
                        (format!("{fail} failed"), DANGER)
                    };
                    pill(ui, &t, c);
                }
            });
        });
    }

    #[cfg(windows)]
    fn refresh_windows_state(&mut self) {
        self.fw_rule = ntp_nts_diag::win::firewall_rule_status();
        self.w32time = ntp_nts_diag::win::w32time_running();
    }

    #[cfg(windows)]
    fn elevate(&mut self, ctx: &egui::Context) {
        match ntp_nts_diag::win::restart_as_admin() {
            Ok(()) => {
                self.reporter
                    .log("Restarting as Administrator; this window will close.");
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(e) => {
                self.reporter
                    .log(format!("Elevation failed: {e}. Continuing normally."));
                self.dialog = Some(Dialog::Result {
                    title: "Elevation failed".into(),
                    body: format!(
                        "Windows did not start an elevated copy ({e}). Continuing normally."
                    ),
                    ok: false,
                });
            }
        }
    }

    #[cfg(windows)]
    fn add_firewall_rule(&mut self) {
        let port = self.s.port;
        self.dialog = Some(match ntp_nts_diag::win::configure_firewall_rule(port) {
            Ok(msg) => {
                self.reporter.log(format!("FIREWALL: {msg}"));
                Dialog::Result {
                    title: "Firewall rule configured".into(),
                    body: format!(
                        "Inbound UDP/{port} is now allowed on the Domain and Private profiles \
                         for the NTP Peer Test Responder."
                    ),
                    ok: true,
                }
            }
            Err(e) => {
                self.reporter.log(format!("FIREWALL ERROR: {e}"));
                Dialog::Result {
                    title: "Firewall rule failed".into(),
                    body: e,
                    ok: false,
                }
            }
        });
        self.refresh_windows_state();
    }

    #[cfg(windows)]
    fn remove_firewall_rule(&mut self) {
        match ntp_nts_diag::win::remove_firewall_rule() {
            Ok(msg) => self.reporter.log(format!("FIREWALL: {msg}")),
            Err(e) => {
                self.reporter.log(format!("FIREWALL ERROR: {e}"));
                self.dialog = Some(Dialog::Result {
                    title: "Could not remove the rule".into(),
                    body: e,
                    ok: false,
                });
            }
        }
        self.refresh_windows_state();
    }

    #[cfg(windows)]
    fn windows_card(&mut self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        let port = self.s.port;
        p.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let sub = if self.is_admin {
                "Running as Administrator"
            } else {
                "Running as a standard user"
            };
            card_title(ui, &self.ic(icon::SHIELD, ""), "Windows", sub);

            let (text, color) = match &self.fw_rule {
                Err(e) => (format!("Firewall status unknown: {e}"), WARNING),
                Ok(None) => ("No firewall rule for the responder".to_string(), p.muted),
                Ok(Some(r)) if !r.enabled => ("Firewall rule exists but is disabled".into(), WARNING),
                Ok(Some(r)) if r.allows_port(port) => (
                    format!("Firewall allows {}/{} · {}", r.protocol, r.local_port, r.profiles),
                    SUCCESS,
                ),
                Ok(Some(r)) => (
                    format!(
                        "Firewall rule allows {}/{}; responder uses UDP/{port}",
                        r.protocol, r.local_port
                    ),
                    WARNING,
                ),
            };
            ui.horizontal_wrapped(|ui| pill(ui, &text, color));
            if port == 123 && self.w32time == Some(true) {
                ui.horizontal_wrapped(|ui| pill(ui, "Windows Time (W32Time) is running and owns UDP/123", WARNING))
                    .response
                    .on_hover_text("Stop it from an elevated prompt with: net stop w32time — or pick another port.");
            }

            ui.add_space(2.0);
            if !self.is_admin
                && primary_button(ui, &self.ic(icon::SHIELD, "Restart as Administrator"), true, ui.available_width())
                    .on_hover_text("Needed to change Windows Firewall")
                    .clicked()
            {
                let ctx = ui.ctx().clone();
                self.elevate(&ctx);
            }
            ui.horizontal_wrapped(|ui| {
                let allow = Button::new(self.ic(icon::FIREWALL, &format!("Allow UDP/{port}")));
                if ui
                    .add_enabled(self.is_admin, allow)
                    .on_hover_text("Creates or refreshes an inbound allow rule (Domain and Private profiles)")
                    .on_disabled_hover_text("Restart as Administrator first")
                    .clicked()
                {
                    self.add_firewall_rule();
                }
                let has_rule = matches!(self.fw_rule, Ok(Some(_)));
                if ui
                    .add_enabled(self.is_admin && has_rule, Button::new(self.ic(icon::DELETE, "Remove rule")))
                    .on_disabled_hover_text(if has_rule {
                        "Restart as Administrator first"
                    } else {
                        "There is no rule to remove"
                    })
                    .clicked()
                {
                    self.remove_firewall_rule();
                }
                if ui
                    .button(self.ic(icon::REFRESH, if self.icons { "" } else { "Refresh" }))
                    .on_hover_text("Refresh the firewall and W32Time status")
                    .clicked()
                {
                    self.refresh_windows_state();
                }
            });
        });
    }

    /// Launch prompts (as in 2.x) and result dialogs.
    #[cfg(windows)]
    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.dialog.clone() else {
            return;
        };
        let p = Palette::for_dark(ctx.global_style().visuals.dark_mode);
        let port = self.s.port;
        let (mut close, mut do_elevate, mut do_firewall) = (false, false, false);
        let modal = egui::Modal::new(egui::Id::unique("dialog"))
            .frame(p.card_frame().inner_margin(Margin::same(22)))
            .show(ctx, |ui| {
                ui.set_width(460.0);
                let (glyph, title, body, color) = match &dialog {
                    Dialog::Elevate => (
                        icon::SHIELD,
                        "Administrator privileges recommended".to_string(),
                        format!(
                            "{APP_NAME} includes an NTP Peer Test Responder. Administrator \
                             privileges are needed to create the optional Windows Firewall rule.\n\n\
                             Restart as Administrator now? Choose Continue to carry on normally: \
                             the client and the responder still work."
                        ),
                        ACCENT,
                    ),
                    Dialog::Firewall => (
                        icon::FIREWALL,
                        "Windows Firewall permission".to_string(),
                        format!(
                            "Allow inbound NTP peer-test traffic through Windows Defender Firewall?\n\n\
                             This creates or refreshes the inbound rule \"{}\": UDP, local port \
                             {port}, Domain and Private profiles.\n\n\
                             Choose Not now if you only test over loopback or manage the firewall \
                             separately.",
                            ntp_nts_diag::win::FIREWALL_RULE_NAME
                        ),
                        ACCENT,
                    ),
                    Dialog::Result { title, body, ok } => (
                        if *ok { icon::CHECK } else { icon::FIREWALL },
                        title.clone(),
                        body.clone(),
                        if *ok { SUCCESS } else { DANGER },
                    ),
                };
                ui.horizontal(|ui| {
                    if self.icons {
                        ui.label(RichText::new(glyph).size(22.0).color(color));
                    }
                    ui.label(RichText::new(title).font(theme::bold(17.0)));
                });
                ui.add_space(4.0);
                ui.label(body);
                ui.add_space(8.0);

                if matches!(dialog, Dialog::Elevate | Dialog::Firewall) {
                    let mut dont_ask = !self.s.startup_prompts;
                    if ui.checkbox(&mut dont_ask, "Don't ask at startup").changed() {
                        self.s.startup_prompts = !dont_ask;
                    }
                    ui.add_space(4.0);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| match &dialog {
                    Dialog::Elevate => {
                        if primary_button(ui, "Restart as Administrator", true, 0.0).clicked() {
                            do_elevate = true;
                        }
                        if ui.button("Continue").clicked() {
                            close = true;
                        }
                    }
                    Dialog::Firewall => {
                        if primary_button(ui, &format!("Allow UDP/{port}"), true, 0.0).clicked() {
                            do_firewall = true;
                        }
                        if ui.button("Not now").clicked() {
                            close = true;
                        }
                    }
                    Dialog::Result { .. } => {
                        if primary_button(ui, "OK", true, 80.0).clicked() {
                            close = true;
                        }
                    }
                });
            });
        if close || modal.should_close() {
            self.dialog = None;
        }
        if do_elevate {
            self.dialog = None;
            self.elevate(ctx);
        }
        if do_firewall {
            self.dialog = None;
            self.add_firewall_rule();
        }
    }

    // --- main area -------------------------------------------------------

    fn kpis(&self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        let s = &self.stats;
        let bad = |n: u64| if n > 0 { DANGER } else { p.text };
        let loss_col = if s.sent == 0 || s.loss_percent() == 0.0 {
            p.text
        } else {
            WARNING
        };
        let tiles = [
            ("Sent", s.sent.to_string(), p.text),
            ("Received", s.received.to_string(), p.text),
            ("Loss", format!("{:.1}%", s.loss_percent()), loss_col),
            ("Failures", s.failures.to_string(), bad(s.failures)),
            ("Timeouts", s.timeouts.to_string(), bad(s.timeouts)),
            (
                "NTS failures",
                s.nts_failures.to_string(),
                bad(s.nts_failures),
            ),
            (
                "Kiss-o'-Death",
                s.kods.to_string(),
                if s.kods > 0 { WARNING } else { p.text },
            ),
            (
                "Authenticated",
                s.authenticated.to_string(),
                if s.authenticated > 0 { SUCCESS } else { p.text },
            ),
        ];
        let gap = 8.0;
        let per_row = 8.0f32.min(
            ((ui.available_width() + gap) / (112.0 + gap))
                .floor()
                .max(1.0),
        );
        let w = (ui.available_width() - gap * (per_row - 1.0)) / per_row;
        ui.spacing_mut().item_spacing.x = gap;
        ui.horizontal_wrapped(|ui| {
            for (label, value, color) in tiles {
                p.card_frame()
                    .inner_margin(Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(w - 24.0 - 2.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(label).size(12.0).color(p.muted));
                            ui.label(RichText::new(value).font(theme::bold(24.0)).color(color));
                        });
                    });
            }
        });
    }

    fn timing_card(&self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        p.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            card_title(
                ui,
                &self.ic(icon::CLOCK, ""),
                "Timing",
                "Per-reply offset and network delay",
            );
            let offsets: Vec<f64> = self.history.iter().map(|h| h.0).collect();
            let delays: Vec<f64> = self.history.iter().map(|h| h.1).collect();
            ui.columns(2, |cols| {
                sparkline(&mut cols[0], &p, "Offset", &offsets, ACCENT, true);
                sparkline(&mut cols[1], &p, "Delay", &delays, VIOLET, false);
            });
            egui::Grid::new("timing")
                .num_columns(7)
                .spacing([18.0, 4.0])
                .show(ui, |ui| {
                    for h in ["", "Last", "Mean", "Min", "Max", "Std dev", "Jitter"] {
                        ui.label(RichText::new(h).size(12.0).color(p.muted));
                    }
                    ui.end_row();
                    for (name, x) in [
                        ("Offset (ms)", &self.stats.offset_ms),
                        ("Delay (ms)", &self.stats.delay_ms),
                    ] {
                        ui.label(name);
                        if x.n == 0 {
                            for _ in 0..6 {
                                ui.label(RichText::new("—").color(p.muted));
                            }
                        } else {
                            for v in [x.last, x.mean, x.min, x.max] {
                                ui.monospace(format!("{v:+.3}"));
                            }
                            ui.monospace(format!("{:.3}", x.stddev()));
                            ui.monospace(format!("{:.3}", x.jitter()));
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn log_card(&mut self, ui: &mut egui::Ui) {
        let p = Palette::of(ui);
        p.card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("Log").font(theme::bold(16.0)));
                ui.add_space(8.0);
                let hint = self.ic(icon::FILTER, "Filter");
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text(hint)
                        .desired_width(220.0)
                        .margin(vec2(8.0, 4.0)),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(self.ic(icon::DELETE, "Clear")).clicked() {
                        self.log.clear();
                    }
                    if ui.button(self.ic(icon::COPY, "Copy")).clicked() && !self.log.is_empty() {
                        ui.ctx().copy_text(self.visible_lines().join("\n"));
                    }
                });
            });
            let lines = self.visible_lines();
            let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
            egui::Frame::new()
                .fill(p.console)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(8.0)
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    if lines.is_empty() {
                        ui.set_min_size(ui.available_size());
                        ui.centered_and_justified(|ui| {
                            ui.label(
                                RichText::new(
                                    "Press Start to query a server, or start the responder.",
                                )
                                .color(p.muted),
                            );
                        });
                        return;
                    }
                    egui::ScrollArea::both()
                        .auto_shrink(false)
                        .stick_to_bottom(true)
                        .show_rows(ui, row_h, lines.len(), |ui, range| {
                            for line in &lines[range] {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(*line).monospace().color(p.log_color(line)),
                                    )
                                    .extend(),
                                );
                            }
                        });
                });
        });
    }
}

// --- small widgets -----------------------------------------------------------

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.14))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(99.0)
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.5).color(color));
        });
}

fn card_title(ui: &mut egui::Ui, glyph: &str, title: &str, subtitle: &str) {
    let p = Palette::of(ui);
    ui.horizontal(|ui| {
        if !glyph.is_empty() {
            ui.label(RichText::new(glyph).size(18.0).color(ACCENT));
        }
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(RichText::new(title).font(theme::bold(16.0)));
            ui.label(RichText::new(subtitle).size(12.0).color(p.muted));
        });
    });
    ui.add_space(4.0);
}

fn field_label(ui: &mut egui::Ui, text: &str) {
    let p = Palette::of(ui);
    ui.add_space(2.0);
    ui.label(RichText::new(text).size(12.0).color(p.muted));
}

fn primary_button(ui: &mut egui::Ui, text: &str, enabled: bool, width: f32) -> egui::Response {
    let hovered_id = ui.next_auto_id();
    let hovered = ui
        .ctx()
        .read_response(hovered_id)
        .is_some_and(|r| r.hovered());
    let fill = if hovered && enabled {
        ACCENT_HOVER
    } else {
        BUTTON
    };
    ui.add_enabled(
        enabled,
        Button::new(
            RichText::new(text)
                .color(Color32::WHITE)
                .font(theme::bold(14.0)),
        )
        .fill(fill)
        .stroke(Stroke::NONE)
        .min_size(vec2(width, 34.0)),
    )
}

/// A small line chart with hover readout.
fn sparkline(
    ui: &mut egui::Ui,
    p: &Palette,
    title: &str,
    values: &[f64],
    color: Color32,
    zero_line: bool,
) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 110.0), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect(
        rect,
        8.0,
        p.console,
        Stroke::new(1.0, p.border),
        egui::StrokeKind::Inside,
    );
    let font = FontId::proportional(12.0);
    painter.text(
        rect.left_top() + vec2(10.0, 8.0),
        Align2::LEFT_TOP,
        title,
        font.clone(),
        p.muted,
    );

    if values.len() < 2 {
        let msg = if values.is_empty() {
            "No samples yet"
        } else {
            "Waiting for a second sample"
        };
        painter.text(rect.center(), Align2::CENTER_CENTER, msg, font, p.muted);
        return;
    }
    let last = *values.last().unwrap();
    painter.text(
        rect.right_top() + vec2(-10.0, 6.0),
        Align2::RIGHT_TOP,
        format!("{last:+.3} ms"),
        theme::bold(14.0),
        color,
    );

    let (mut lo, mut hi) = values
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), &v| {
            (a.min(v), b.max(v))
        });
    if zero_line {
        lo = lo.min(0.0);
        hi = hi.max(0.0);
    }
    if (hi - lo).abs() < 1e-6 {
        lo -= 1.0;
        hi += 1.0;
    }
    let pad = (hi - lo) * 0.1;
    let (lo, hi) = (lo - pad, hi + pad);
    let plot = egui::Rect::from_min_max(rect.min + vec2(10.0, 28.0), rect.max - vec2(10.0, 18.0));
    let n = values.len();
    let x_of = |i: usize| plot.left() + plot.width() * i as f32 / (n - 1) as f32;
    let y_of = |v: f64| plot.bottom() - plot.height() * ((v - lo) / (hi - lo)) as f32;

    if zero_line && lo < 0.0 && hi > 0.0 {
        let y = y_of(0.0);
        painter.add(Shape::dashed_line(
            &[pos2(plot.left(), y), pos2(plot.right(), y)],
            Stroke::new(1.0, p.border),
            4.0,
            4.0,
        ));
    }
    let pts: Vec<egui::Pos2> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| pos2(x_of(i), y_of(v)))
        .collect();
    // Soft area under the line.
    let base = plot.bottom();
    for w in pts.windows(2) {
        painter.add(Shape::convex_polygon(
            vec![w[0], w[1], pos2(w[1].x, base), pos2(w[0].x, base)],
            color.gamma_multiply(0.10),
            Stroke::NONE,
        ));
    }
    painter.add(Shape::line(pts.clone(), Stroke::new(2.0, color)));
    painter.circle_filled(*pts.last().unwrap(), 3.5, color);
    painter.text(
        rect.left_bottom() + vec2(10.0, -4.0),
        Align2::LEFT_BOTTOM,
        format!(
            "min {:+.2}  max {:+.2}",
            values.iter().cloned().fold(f64::INFINITY, f64::min),
            values.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
        ),
        FontId::proportional(11.0),
        p.muted,
    );

    if let Some(pos) = resp.hover_pos() {
        let i = (((pos.x - plot.left()) / plot.width()) * (n - 1) as f32)
            .round()
            .clamp(0.0, (n - 1) as f32) as usize;
        let x = x_of(i);
        painter.line_segment(
            [pos2(x, plot.top()), pos2(x, plot.bottom())],
            Stroke::new(1.0, p.muted),
        );
        painter.circle_filled(pts[i], 4.0, color);
        let text = format!("#{}  {:+.3} ms", i + 1, values[i]);
        let anchor = if x > rect.center().x {
            Align2::RIGHT_BOTTOM
        } else {
            Align2::LEFT_BOTTOM
        };
        let off = if x > rect.center().x {
            vec2(-8.0, -6.0)
        } else {
            vec2(8.0, -6.0)
        };
        painter.text(
            pts[i] + off,
            anchor,
            text,
            FontId::proportional(12.0),
            p.text,
        );
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        if self.responder.is_some() || self.suite_running {
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
        let (start, stop) = ui.ctx().input(|i| {
            (
                i.modifiers.command && i.key_pressed(Key::Enter),
                i.key_pressed(Key::Escape),
            )
        });
        if start {
            self.start_client();
        }
        // Esc closes an open dialog instead of stopping the run.
        #[cfg(windows)]
        let stop = stop && self.dialog.is_none();
        if stop {
            self.stop_client();
        }

        let panel_fill = ui.visuals().panel_fill;
        let p = Palette::of(ui);
        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(p.card)
                    .inner_margin(Margin::symmetric(16, 10))
                    .stroke(Stroke::new(1.0, p.border)),
            )
            .show(ui, |ui| self.header(ui));
        egui::Panel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(p.card)
                    .inner_margin(Margin::symmetric(16, 4))
                    .stroke(Stroke::new(1.0, p.border)),
            )
            .show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("controls")
            .resizable(false)
            .exact_size(SIDEBAR_WIDTH)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(panel_fill))
            .show(ui, |ui| {
                // Always show the scrollbar: the Windows card is below the fold at the
                // default size, and egui's floating bars are invisible until hovered.
                ui.spacing_mut().scroll = egui::style::ScrollStyle {
                    dormant_handle_opacity: 0.35,
                    ..egui::style::ScrollStyle::floating()
                };
                // The margins sit inside the scroll area, so the bar stays within the panel.
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .show(ui, |ui| {
                        egui::Frame::new()
                            .inner_margin(Margin {
                                left: 16,
                                right: 6,
                                top: 14,
                                bottom: 14,
                            })
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 12.0;
                                self.client_card(ui);
                                self.responder_card(ui);
                                #[cfg(windows)]
                                self.windows_card(ui);
                            });
                    });
            });
        egui::CentralPanel::default_margins()
            .frame(egui::Frame::new().fill(panel_fill).inner_margin(Margin {
                left: 6,
                right: 16,
                top: 14,
                bottom: 14,
            }))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 12.0;
                self.kpis(ui);
                self.timing_card(ui);
                self.log_card(ui);
            });
        #[cfg(windows)]
        {
            let ctx = ui.ctx().clone();
            self.dialogs(&ctx);
        }
        let ctx = ui.ctx().clone();
        self.capture_tick(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if self.capture.is_some() {
            return;
        }
        self.s.mode = self.mode.name().into();
        eframe::set_value(storage, eframe::APP_KEY, &self.s);
    }
}

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("{APP_NAME} {APP_VERSION}"))
            .with_inner_size(if std::env::var_os(CAPTURE_ENV).is_some() {
                [1440.0, 880.0]
            } else {
                [1280.0, 860.0]
            })
            .with_min_inner_size([1000.0, 680.0])
            .with_icon(theme::window_icon()),
        // A screenshot run always uses the default window size.
        persist_window: std::env::var_os(CAPTURE_ENV).is_none(),
        // …and a throwaway store, so it neither reads nor overwrites the user's settings.
        persistence_path: std::env::var_os(CAPTURE_ENV)
            .map(|_| std::env::temp_dir().join(format!("ntpnts-capture-{}", std::process::id()))),
        ..Default::default()
    };
    eframe::run_native(APP_NAME, options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

fn save_png(path: &std::path::Path, image: &egui::ColorImage) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let [w, h] = image.size;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header().map_err(|e| e.to_string())?;
    writer
        .write_image_data(image.as_raw())
        .map_err(|e| e.to_string())
}
