//! egui front end.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};

use ntp_nts_diag::client::{self, ClientConfig};
use ntp_nts_diag::report::{Event, Reporter};
use ntp_nts_diag::responder::{FaultMode, Responder};
use ntp_nts_diag::stats::ClientStats;
use ntp_nts_diag::{APP_NAME, APP_VERSION, StopFlag, selftest};

const MAX_LOG_LINES: usize = 200_000;

pub struct App {
    rx: Receiver<Event>,
    reporter: Reporter,

    target: String,
    count: u32,
    delay_ms: u32,
    nts: bool,
    skip_verify: bool,
    log_to_file: bool,
    log_path: Option<PathBuf>,
    client_stop: Option<StopFlag>,
    stats: ClientStats,

    bind: String,
    port: u16,
    mode: FaultMode,
    responder: Option<Responder>,
    suite_running: bool,

    log: Vec<String>,
    filter: String,
    is_admin: bool,
}

impl App {
    pub fn new(ctx: &egui::Context) -> Self {
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
        let d = ClientConfig::default();
        let app = App {
            rx,
            reporter,
            target: d.target,
            count: d.count,
            delay_ms: d.delay.as_millis() as u32,
            nts: d.nts,
            skip_verify: d.skip_verify,
            log_to_file: false,
            log_path: None,
            client_stop: None,
            stats: ClientStats::default(),
            bind: "0.0.0.0".into(),
            port: 123,
            mode: FaultMode::Valid,
            responder: None,
            suite_running: false,
            log: Vec::new(),
            filter: String::new(),
            is_admin,
        };
        #[cfg(windows)]
        app.reporter.log(format!(
            "Windows privilege status: Administrator={}",
            if is_admin { "YES" } else { "NO" }
        ));
        app
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Log(line) => {
                    self.log.push(line);
                    if self.log.len() > MAX_LOG_LINES {
                        self.log.drain(..MAX_LOG_LINES / 10);
                    }
                }
                Event::Stats(s) => self.stats = s,
                Event::ClientDone => self.client_stop = None,
                Event::SuiteDone { .. } => self.suite_running = false,
                Event::ResponderStopped => {}
            }
        }
        if self.responder.as_ref().is_some_and(Responder::is_finished) {
            self.responder = None;
        }
    }

    fn start_client(&mut self) {
        if self.log_to_file && self.log_path.is_none() {
            self.reporter
                .log("ERROR: Log to file is checked but no file is selected.");
            return;
        }
        if self.target.trim().is_empty() {
            self.reporter.log("ERROR: Server is empty.");
            return;
        }
        self.log.clear();
        self.stats = ClientStats::default();
        let cfg = ClientConfig {
            target: self.target.trim().to_string(),
            count: self.count,
            delay: Duration::from_millis(self.delay_ms as u64),
            nts: self.nts,
            skip_verify: self.skip_verify,
            ..ClientConfig::default()
        };
        let stop = StopFlag::new();
        self.client_stop = Some(stop.clone());
        let rep = self.reporter.clone();
        thread::spawn(move || client::run(&cfg, &rep, &stop));
    }

    fn start_responder(&mut self) {
        let ip: IpAddr = match self.bind.trim().parse() {
            Ok(ip) => ip,
            Err(_) => {
                self.reporter.log(format!(
                    "PEER TEST ERROR: '{}' is not an IPv4/IPv6 address.",
                    self.bind.trim()
                ));
                return;
            }
        };
        match Responder::start(
            SocketAddr::new(ip, self.port),
            self.mode,
            self.reporter.clone(),
        ) {
            Ok(r) => self.responder = Some(r),
            Err(e) => self.reporter.log(format!("PEER TEST ERROR: {e}")),
        }
    }

    fn start_suite(&mut self) {
        self.suite_running = true;
        let rep = self.reporter.clone();
        thread::spawn(move || selftest::run(&rep));
    }

    fn set_log_file(&mut self) {
        let path = if self.log_to_file {
            self.log_path.as_deref()
        } else {
            None
        };
        if let Err(e) = self.reporter.set_log_file(path) {
            self.reporter
                .log(format!("ERROR: cannot open log file: {e}"));
        }
    }

    fn ui_config(&mut self, ui: &mut egui::Ui) {
        let running = self.client_stop.is_some();
        ui.group(|ui| {
            ui.strong("Configuration");
            egui::Grid::new("cfg").num_columns(4).spacing([10.0, 6.0]).show(ui, |ui| {
                ui.label("Server (IP/FQDN[:port]):");
                ui.add_enabled_ui(!running, |ui| {
                    ui.add_sized([260.0, 20.0], egui::TextEdit::singleline(&mut self.target))
                })
                .inner
                .on_hover_text("host, host:port or [IPv6]:port. The port is the NTS-KE port (default 4460) with NTS, otherwise the NTP port (default 123).");
                ui.label("Number of requests:");
                ui.add_enabled(!running, egui::DragValue::new(&mut self.count).range(1..=100_000));
                ui.end_row();

                ui.label("Delay (ms):");
                ui.add_enabled(!running, egui::DragValue::new(&mut self.delay_ms).range(0..=600_000).speed(10));
                ui.add_enabled(!running, egui::Checkbox::new(&mut self.nts, "Enable NTS (TCP 4460)"));
                ui.add_enabled(!running && self.nts, egui::Checkbox::new(&mut self.skip_verify, "Skip TLS certificate verification"));
                ui.end_row();
            });
            ui.horizontal(|ui| {
                if ui.checkbox(&mut self.log_to_file, "Log to file").changed() {
                    self.set_log_file();
                }
                if ui.add_enabled(self.log_to_file, egui::Button::new("Select log file…")).clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("Text files", &["txt"])
                        .add_filter("Log files", &["log"])
                        .set_file_name("ntp-nts-diagnostic.log")
                        .save_file()
                    {
                        self.log_path = Some(p);
                        self.set_log_file();
                    }
                ui.label(self.log_path.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "No file selected".into()));
            });
            ui.horizontal(|ui| {
                if ui.add_enabled(!running, egui::Button::new("Start requests")).clicked() {
                    self.start_client();
                }
                if ui.add_enabled(running, egui::Button::new("Stop")).clicked()
                    && let Some(s) = &self.client_stop {
                        s.stop();
                        self.reporter.log("Stop requested; waiting for the active network operation to finish…");
                    }
            });
        });
    }

    fn ui_responder(&mut self, ui: &mut egui::Ui) {
        let active = self.responder.is_some();
        ui.group(|ui| {
            ui.strong("NTP Peer Test Responder");
            ui.horizontal(|ui| {
                ui.label("Bind:");
                ui.add_enabled(
                    !active,
                    egui::TextEdit::singleline(&mut self.bind).desired_width(130.0),
                );
                ui.label("UDP port:");
                ui.add_enabled(
                    !active,
                    egui::DragValue::new(&mut self.port).range(1..=65535),
                );
                ui.label("Response mode:");
                ui.add_enabled_ui(!active, |ui| {
                    egui::ComboBox::from_id_salt("mode")
                        .selected_text(self.mode.name())
                        .width(170.0)
                        .show_ui(ui, |ui| {
                            for m in FaultMode::ALL {
                                ui.selectable_value(&mut self.mode, m, m.name())
                                    .on_hover_text(m.description());
                            }
                        });
                });
                if ui
                    .add_enabled(!active, egui::Button::new("Start responder"))
                    .clicked()
                {
                    self.start_responder();
                }
                if ui
                    .add_enabled(active, egui::Button::new("Stop responder"))
                    .clicked()
                    && let Some(r) = self.responder.take()
                {
                    self.reporter.log("NTP peer test responder stop requested.");
                    r.stop();
                }
                if ui
                    .add_enabled(
                        !self.suite_running,
                        egui::Button::new("Run self-test suite"),
                    )
                    .clicked()
                {
                    self.start_suite();
                }
            });
            ui.label(
                RichText::new(format!("{}: {}", self.mode.name(), self.mode.description())).weak(),
            );
            #[cfg(windows)]
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Administrator: {}",
                    if self.is_admin { "YES" } else { "NO" }
                ));
                if !self.is_admin
                    && ui
                        .button("Restart as Administrator")
                        .on_hover_text("Required to add the Windows Firewall rule")
                        .clicked()
                {
                    match ntp_nts_diag::win::restart_as_admin() {
                        Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => self
                            .reporter
                            .log(format!("Elevation failed: {e}. Continuing normally.")),
                    }
                }
                let fw = ui.add_enabled(
                    self.is_admin,
                    egui::Button::new(format!(
                        "Allow inbound UDP/{} in Windows Firewall",
                        self.port
                    )),
                );
                if fw
                    .on_hover_text(
                        "Creates or refreshes an inbound allow rule (Domain and Private profiles)",
                    )
                    .clicked()
                {
                    match ntp_nts_diag::win::configure_firewall_rule(self.port) {
                        Ok(msg) => self.reporter.log(format!("FIREWALL: {msg}")),
                        Err(e) => self.reporter.log(format!("FIREWALL ERROR: {e}")),
                    }
                }
            });
        });
    }

    fn ui_stats(&self, ui: &mut egui::Ui) {
        let s = &self.stats;
        ui.group(|ui| {
            ui.strong("Real-Time Statistics");
            ui.horizontal_wrapped(|ui| {
                let item = |ui: &mut egui::Ui, label: &str, v: String| {
                    ui.label(label);
                    ui.label(RichText::new(v).strong());
                    ui.add_space(12.0);
                };
                item(ui, "Sent:", s.sent.to_string());
                item(ui, "Received:", s.received.to_string());
                item(ui, "Loss:", format!("{:.1}%", s.loss_percent()));
                item(ui, "Failures:", s.failures.to_string());
                item(ui, "Timeouts:", s.timeouts.to_string());
                item(ui, "NTS failures:", s.nts_failures.to_string());
                item(ui, "KoD packets:", s.kods.to_string());
                item(ui, "Authenticated:", s.authenticated.to_string());
            });
            egui::Grid::new("timing")
                .num_columns(6)
                .spacing([14.0, 2.0])
                .show(ui, |ui| {
                    for h in ["", "last", "mean", "min / max", "stddev", "jitter"] {
                        ui.label(RichText::new(h).weak());
                    }
                    ui.end_row();
                    for (name, x) in [("Offset (ms)", &s.offset_ms), ("Delay (ms)", &s.delay_ms)] {
                        ui.label(name);
                        if x.n == 0 {
                            for _ in 0..5 {
                                ui.label("—");
                            }
                        } else {
                            ui.monospace(format!("{:+.3}", x.last));
                            ui.monospace(format!("{:+.3}", x.mean));
                            ui.monospace(format!("{:+.3} / {:+.3}", x.min, x.max));
                            ui.monospace(format!("{:.3}", x.stddev()));
                            ui.monospace(format!("{:.3}", x.jitter()));
                        }
                        ui.end_row();
                    }
                });
        });
    }

    fn ui_log(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Running Log");
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(200.0)
                    .hint_text("text to match"),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Copy log").clicked() && !self.log.is_empty() {
                    ui.ctx().copy_text(self.visible_lines().join("\n"));
                }
                if ui.button("Clear log").clicked() {
                    self.log.clear();
                }
            });
        });
        let lines = self.visible_lines();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        egui::Frame::new()
            .fill(Color32::from_rgb(0x1e, 0x1e, 0x1e))
            .inner_margin(6.0)
            .corner_radius(4.0)
            .show(ui, |ui| {
                egui::ScrollArea::both()
                    .auto_shrink(false)
                    .stick_to_bottom(true)
                    .show_rows(ui, row_h, lines.len(), |ui, range| {
                        for line in &lines[range] {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(*line).monospace().color(line_color(line)),
                                )
                                .extend(),
                            );
                        }
                    });
            });
    }

    fn visible_lines(&self) -> Vec<&str> {
        let f = self.filter.trim().to_lowercase();
        self.log
            .iter()
            .map(String::as_str)
            .filter(|l| f.is_empty() || l.to_lowercase().contains(&f))
            .collect()
    }
}

fn line_color(line: &str) -> Color32 {
    if line.contains("ERROR") || line.contains("[FAIL]") || line.contains("FAILED") {
        Color32::from_rgb(0xf4, 0x87, 0x71)
    } else if line.contains("WARNING") {
        Color32::from_rgb(0xdc, 0xdc, 0x8b)
    } else if line.contains("[PASS]") || line.contains("AUTHENTICATED") || line.contains("SUCCESS")
    {
        Color32::from_rgb(0x89, 0xd1, 0x85)
    } else if line.contains("SUMMARY") || line.contains("===") {
        Color32::from_rgb(0x9c, 0xdc, 0xfe)
    } else {
        Color32::from_rgb(0xcc, 0xcc, 0xcc)
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        if self.responder.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.ui_config(ui);
            ui.add_space(6.0);
            self.ui_responder(ui);
            ui.add_space(6.0);
            self.ui_stats(ui);
            ui.add_space(6.0);
            self.ui_log(ui);
        });
    }
}

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("{APP_NAME} {APP_VERSION}"))
            .with_inner_size([1040.0, 780.0])
            .with_min_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|cc| Ok(Box::new(App::new(&cc.egui_ctx)))),
    )
}
