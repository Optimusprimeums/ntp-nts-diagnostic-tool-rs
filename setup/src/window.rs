//! The setup window: what will be installed and where, a progress bar while
//! it copies, then the result.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Layout,
    Margin, ProgressBar, RichText, Stroke, vec2,
};
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};

use crate::install::{self, NAME, VERSION};

const ACCENT: Color32 = Color32::from_rgb(0x2F, 0x7D, 0xF6);
const BUTTON: Color32 = Color32::from_rgb(0x1F, 0x5F, 0xD6);
const DANGER: Color32 = Color32::from_rgb(0xD9, 0x3F, 0x3F);
const SUCCESS: Color32 = Color32::from_rgb(0x1E, 0x9E, 0x5A);

#[derive(Default)]
struct Progress {
    done: u64,
    name: String,
    result: Option<Result<PathBuf, String>>,
}

enum Page {
    Ready,
    Working,
    Done(PathBuf),
    Failed(String),
}

struct Setup {
    page: Page,
    previous: Option<String>,
    dir: String,
    total: u64,
    progress: Arc<Mutex<Progress>>,
    launch: bool,
}

impl Setup {
    fn begin(&mut self, ctx: &egui::Context) {
        self.page = Page::Working;
        let progress = Arc::new(Mutex::new(Progress::default()));
        self.progress = progress.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // The Start menu shortcut is made through COM.
            let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            let result = install::put_files(&mut |done, name| {
                let mut p = progress.lock().unwrap();
                p.done = done;
                p.name = name.to_string();
                ctx.request_repaint();
            });
            progress.lock().unwrap().result = Some(result);
            ctx.request_repaint();
        });
    }

    fn body(&mut self, ui: &mut egui::Ui) {
        let muted = ui.visuals().weak_text_color();
        match &self.page {
            Page::Ready => {
                let what = match &self.previous {
                    Some(old) if old == VERSION => {
                        format!("This reinstalls version {VERSION}. Your settings are kept.")
                    }
                    Some(old) => {
                        format!("This upgrades version {old} to {VERSION}. Your settings are kept.")
                    }
                    None => format!(
                        "This installs the {NAME} {VERSION} for you only. \
                         No administrator rights are needed."
                    ),
                };
                ui.label(what);
                ui.add_space(6.0);
                ui.label(RichText::new("Folder").color(muted));
                ui.label(RichText::new(&self.dir).monospace());
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "Adds the program, the ntpnts command-line tool and a Start menu entry.",
                    )
                    .color(muted),
                );
                if self.previous.is_some() {
                    ui.label(RichText::new("Close the tool before you continue.").color(muted));
                }
            }
            Page::Working => {
                let (done, name) = {
                    let p = self.progress.lock().unwrap();
                    (p.done, p.name.clone())
                };
                ui.label(format!("Installing the {NAME} {VERSION}…"));
                ui.add_space(8.0);
                let f = if self.total == 0 {
                    0.0
                } else {
                    done as f32 / self.total as f32
                };
                ui.add(
                    ProgressBar::new(f.min(1.0))
                        .fill(ACCENT)
                        .desired_height(10.0),
                );
                ui.add_space(4.0);
                let status = match name.as_str() {
                    "" => "Starting".to_string(),
                    "Start menu" => "Adding the Start menu entry".to_string(),
                    n => format!("Copying {n}"),
                };
                ui.label(RichText::new(status).color(muted));
            }
            Page::Done(_) => {
                ui.label(
                    RichText::new(format!("The {NAME} {VERSION} is installed."))
                        .color(SUCCESS)
                        .strong(),
                );
                ui.add_space(6.0);
                ui.label(
                    "You'll find it in the Start menu. To remove it later, use \
                     Settings > Apps > Installed apps.",
                );
                ui.add_space(8.0);
                ui.checkbox(&mut self.launch, format!("Start the {NAME} now"));
            }
            Page::Failed(why) => {
                ui.label(RichText::new("Setup did not finish").color(DANGER).strong());
                ui.add_space(6.0);
                ui.label(why.as_str());
            }
        }
    }
}

fn primary(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add(
        egui::Button::new(RichText::new(text).color(Color32::WHITE).strong())
            .fill(BUTTON)
            .stroke(Stroke::NONE)
            .min_size(vec2(96.0, 32.0)),
    )
    .clicked()
}

fn secondary(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add(egui::Button::new(text).min_size(vec2(96.0, 32.0)))
        .clicked()
}

impl eframe::App for Setup {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if matches!(self.page, Page::Working)
            && let Some(result) = self.progress.lock().unwrap().result.take()
        {
            self.page = match result {
                Ok(exe) => Page::Done(exe),
                Err(why) => Page::Failed(why),
            };
        }

        let card = ui.visuals().extreme_bg_color;
        egui::Panel::bottom("buttons")
            .frame(
                egui::Frame::new()
                    .fill(card)
                    .inner_margin(Margin::symmetric(20, 12)),
            )
            .show(ui, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    match &self.page {
                        Page::Ready => {
                            let go = if self.previous.is_some() {
                                "Upgrade"
                            } else {
                                "Install"
                            };
                            if primary(ui, go) {
                                self.begin(&ctx);
                            }
                            if secondary(ui, "Cancel") {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        }
                        Page::Working => {
                            ui.add_enabled(
                                false,
                                egui::Button::new("Install").min_size(vec2(96.0, 32.0)),
                            );
                        }
                        Page::Done(exe) => {
                            if primary(ui, "Finish") {
                                if self.launch {
                                    let _ = std::process::Command::new(exe)
                                        .current_dir(exe.parent().unwrap_or(exe))
                                        .spawn();
                                }
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        }
                        Page::Failed(_) => {
                            if primary(ui, "Try again") {
                                self.begin(&ctx);
                            }
                            if secondary(ui, "Close") {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        }
                    }
                });
            });
        egui::CentralPanel::default_margins()
            .frame(egui::Frame::new().inner_margin(Margin::symmetric(24, 20)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(40.0, 40.0), egui::Sense::hover());
                    clock(ui.painter(), rect);
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(NAME)
                                .font(FontId::proportional(20.0))
                                .strong(),
                        );
                        ui.label(
                            RichText::new(format!("Setup · version {VERSION}"))
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                });
                ui.add_space(16.0);
                self.body(ui);
            });
    }
}

/// The app's clock mark, drawn to match its icon.
fn clock(painter: &egui::Painter, rect: egui::Rect) {
    let c = rect.center();
    let r = rect.width() / 2.0;
    painter.circle_filled(c, r, ACCENT);
    let s = r / 31.0;
    let hand = |deg: f32, len: f32, w: f32| {
        let a = deg.to_radians();
        let end = c + vec2(a.sin(), -a.cos()) * len * s;
        painter.line_segment([c, end], Stroke::new(w * s, Color32::WHITE));
    };
    hand(300.0, 17.0, 5.2);
    hand(60.0, 23.0, 4.0);
    painter.circle_filled(c, 4.0 * s, Color32::WHITE);
}

/// Segoe UI where Windows has it, egui's own font otherwise.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let windir = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    if let Ok(bytes) = std::fs::read(PathBuf::from(windir).join("Fonts").join("segoeui.ttf")) {
        fonts
            .font_data
            .insert("segoe".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(list) = fonts.families.get_mut(&FontFamily::Proportional) {
            list.insert(0, "segoe".into());
        }
    }
    ctx.set_fonts(fonts);
    ctx.all_styles_mut(|style| {
        style.spacing.button_padding = vec2(14.0, 6.0);
        for w in [
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.active,
        ] {
            w.corner_radius = CornerRadius::same(6);
        }
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(14.5));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(14.5));
    });
}

fn icon() -> egui::IconData {
    // The same mark as the window icon of the tool, at 64 px.
    const N: u32 = 64;
    let c = (N as f32 - 1.0) / 2.0;
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    for y in 0..N {
        for x in 0..N {
            let (dx, dy) = (x as f32 - c, y as f32 - c);
            let d = (dx * dx + dy * dy).sqrt();
            let disc = (30.5 - d).clamp(0.0, 1.0);
            let i = ((y * N + x) * 4) as usize;
            rgba[i..i + 4].copy_from_slice(&[
                ACCENT.r(),
                ACCENT.g(),
                ACCENT.b(),
                (disc * 255.0) as u8,
            ]);
        }
    }
    egui::IconData {
        rgba,
        width: N,
        height: N,
    }
}

pub fn run() -> i32 {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("{NAME} Setup"))
            .with_inner_size([560.0, 340.0])
            .with_resizable(false)
            .with_maximize_button(false)
            .with_icon(icon()),
        ..Default::default()
    };
    let setup = Setup {
        page: Page::Ready,
        previous: install::installed_version(),
        dir: install::install_dir().map_or_else(String::new, |d| d.display().to_string()),
        total: install::total_bytes(),
        progress: Arc::default(),
        launch: true,
    };
    match eframe::run_native(
        &format!("{NAME} Setup"),
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(setup))
        }),
    ) {
        Ok(()) => 0,
        Err(e) => {
            install::complain(&format!("Setup could not open its window.\n\n{e}"));
            1
        }
    }
}
