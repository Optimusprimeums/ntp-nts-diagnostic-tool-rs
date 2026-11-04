//! Visual design: fonts, colours, widget styling, icons and the window icon.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke,
    TextStyle, Theme, Vec2,
};

pub const ACCENT: Color32 = Color32::from_rgb(0x2F, 0x7D, 0xF6);
/// Primary button fill: deep enough for white text (WCAG AA).
pub const BUTTON: Color32 = Color32::from_rgb(0x1F, 0x5F, 0xD6);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x2A, 0x6E, 0xE8);
pub const SUCCESS: Color32 = Color32::from_rgb(0x22, 0xA0, 0x6B);
pub const WARNING: Color32 = Color32::from_rgb(0xD9, 0x8E, 0x04);
pub const DANGER: Color32 = Color32::from_rgb(0xE0, 0x4F, 0x4F);
/// Second chart series (delay).
pub const VIOLET: Color32 = Color32::from_rgb(0x9B, 0x6B, 0xF2);

/// Segoe Fluent Icons / Segoe MDL2 Assets code points.
pub mod icon {
    pub const PLAY: char = '\u{E768}';
    pub const STOP: char = '\u{E71A}';
    pub const COPY: char = '\u{E8C8}';
    pub const DELETE: char = '\u{E74D}';
    pub const FOLDER: char = '\u{E838}';
    pub const SHIELD: char = '\u{EA18}';
    pub const CLOCK: char = '\u{E917}';
    pub const FILTER: char = '\u{E71C}';
    pub const CHECK: char = '\u{E73E}';
    pub const NETWORK: char = '\u{E968}';
    pub const DIAGNOSTIC: char = '\u{E9D9}';
    pub const SUN: char = '\u{E706}';
    pub const MOON: char = '\u{E708}';
    pub const SYSTEM: char = '\u{E7F8}';
    pub const FIREWALL: char = '\u{E83D}';
}

/// Colours that depend on light/dark mode.
#[derive(Clone, Copy)]
pub struct Palette {
    pub dark: bool,
    pub card: Color32,
    pub border: Color32,
    pub console: Color32,
    pub muted: Color32,
    pub text: Color32,
}

impl Palette {
    pub fn of(ui: &egui::Ui) -> Self {
        Self::for_dark(ui.visuals().dark_mode)
    }

    pub fn for_dark(dark: bool) -> Self {
        if dark {
            Palette {
                dark,
                card: Color32::from_rgb(0x1F, 0x22, 0x2A),
                border: Color32::from_rgb(0x2E, 0x33, 0x3D),
                console: Color32::from_rgb(0x12, 0x14, 0x19),
                muted: Color32::from_rgb(0x8B, 0x93, 0xA1),
                text: Color32::from_rgb(0xE6, 0xE8, 0xEC),
            }
        } else {
            Palette {
                dark,
                card: Color32::WHITE,
                border: Color32::from_rgb(0xCF, 0xD5, 0xDE),
                console: Color32::from_rgb(0xF4, 0xF6, 0xF9),
                muted: Color32::from_rgb(0x4B, 0x55, 0x63),
                text: Color32::from_rgb(0x1F, 0x23, 0x2B),
            }
        }
    }

    pub fn card_frame(&self) -> egui::Frame {
        egui::Frame::new()
            .fill(self.card)
            .stroke(Stroke::new(1.0, self.border))
            .corner_radius(10.0)
            .inner_margin(Margin::same(14))
    }

    /// Log line colour, by content.
    pub fn log_color(&self, line: &str) -> Color32 {
        let (err, warn, ok, info) = if self.dark {
            (
                Color32::from_rgb(0xF4, 0x87, 0x71),
                Color32::from_rgb(0xE5, 0xC0, 0x7B),
                Color32::from_rgb(0x7E, 0xD3, 0x9A),
                Color32::from_rgb(0x8C, 0xC4, 0xFF),
            )
        } else {
            (
                Color32::from_rgb(0xC0, 0x30, 0x30),
                Color32::from_rgb(0x9A, 0x62, 0x00),
                Color32::from_rgb(0x1A, 0x7F, 0x4B),
                Color32::from_rgb(0x1F, 0x5F, 0xC4),
            )
        };
        if line.contains("ERROR") || line.contains("[FAIL]") || line.contains("FAILED") {
            err
        } else if line.contains("WARNING") {
            warn
        } else if line.contains("[PASS]")
            || line.contains("AUTHENTICATED")
            || line.contains("SUCCESS")
        {
            ok
        } else if line.contains("SUMMARY") || line.contains("===") {
            info
        } else {
            self.text
        }
    }
}

fn read_font(names: &[&str]) -> Option<Vec<u8>> {
    let dir = std::env::var_os("WINDIR")
        .map(|w| std::path::PathBuf::from(w).join("Fonts"))
        .unwrap_or_else(|| "C:\\Windows\\Fonts".into());
    names.iter().find_map(|n| std::fs::read(dir.join(n)).ok())
}

/// Use the native Windows fonts when available (Segoe UI, Cascadia Mono, Segoe
/// Fluent Icons) and fall back to egui's bundled fonts elsewhere.
/// Returns true if an icon font was loaded.
pub fn install_fonts(ctx: &egui::Context) -> bool {
    let mut fonts = FontDefinitions::default();
    let add = |fonts: &mut FontDefinitions, key: &str, data: Vec<u8>| {
        fonts
            .font_data
            .insert(key.to_string(), Arc::new(FontData::from_owned(data)));
    };

    let mut prop_front = Vec::new();
    if let Some(d) = read_font(&["segoeui.ttf"]) {
        add(&mut fonts, "ui", d);
        prop_front.push("ui".to_string());
    }
    let icons = read_font(&["SegoeIcons.ttf", "segmdl2.ttf"]);
    let has_icons = icons.is_some();
    if let Some(d) = icons {
        add(&mut fonts, "icons", d);
        prop_front.push("icons".to_string());
    }
    let prop = fonts.families.entry(FontFamily::Proportional).or_default();
    for (i, k) in prop_front.iter().enumerate() {
        prop.insert(i, k.clone());
    }

    if let Some(d) = read_font(&["CascadiaMono.ttf", "consola.ttf"]) {
        add(&mut fonts, "mono", d);
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "mono".into());
    }

    // Semibold family for headings and figures.
    let mut bold = Vec::new();
    if let Some(d) = read_font(&["seguisb.ttf", "segoeuib.ttf"]) {
        add(&mut fonts, "bold", d);
        bold.push("bold".to_string());
    }
    bold.extend(fonts.families[&FontFamily::Proportional].iter().cloned());
    fonts.families.insert(FontFamily::Name("bold".into()), bold);

    ctx.set_fonts(fonts);
    has_icons
}

pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

fn style_for(style: &mut egui::Style, dark: bool) {
    let p = Palette::for_dark(dark);
    style.text_styles = [
        (TextStyle::Heading, bold(17.0)),
        (TextStyle::Body, FontId::proportional(14.0)),
        (TextStyle::Button, FontId::proportional(14.0)),
        (TextStyle::Small, FontId::proportional(12.0)),
        (TextStyle::Monospace, FontId::monospace(12.5)),
    ]
    .into();

    let s = &mut style.spacing;
    s.item_spacing = Vec2::new(8.0, 8.0);
    s.button_padding = Vec2::new(12.0, 5.0);
    s.interact_size.y = 28.0;
    s.combo_height = 300.0;

    let v = &mut style.visuals;
    v.panel_fill = if dark {
        Color32::from_rgb(0x16, 0x18, 0x1D)
    } else {
        Color32::from_rgb(0xEC, 0xEF, 0xF3)
    };
    v.window_fill = p.card;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.faint_bg_color = p.card;
    v.extreme_bg_color = p.console;
    v.text_edit_bg_color = Some(if dark {
        Color32::from_rgb(0x15, 0x17, 0x1C)
    } else {
        Color32::from_rgb(0xF6, 0xF7, 0xF9)
    });
    v.selection.bg_fill = ACCENT.gamma_multiply(if dark { 0.55 } else { 0.35 });
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARNING;
    v.error_fg_color = DANGER;

    let (rest, hover, press) = if dark {
        (
            Color32::from_rgb(0x2A, 0x2E, 0x38),
            Color32::from_rgb(0x34, 0x39, 0x45),
            Color32::from_rgb(0x3D, 0x43, 0x51),
        )
    } else {
        (
            Color32::from_rgb(0xE8, 0xEB, 0xF0),
            Color32::from_rgb(0xDD, 0xE2, 0xE9),
            Color32::from_rgb(0xD0, 0xD6, 0xDF),
        )
    };
    let r = CornerRadius::same(6);
    let w = &mut v.widgets;
    w.noninteractive.corner_radius = r;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    for (wv, fill) in [
        (&mut w.inactive, rest),
        (&mut w.hovered, hover),
        (&mut w.active, press),
        (&mut w.open, hover),
    ] {
        wv.corner_radius = r;
        wv.bg_fill = fill;
        wv.weak_bg_fill = fill;
        wv.expansion = 0.0;
    }
    let control_border = if dark {
        p.border
    } else {
        Color32::from_rgb(0xB8, 0xC0, 0xCC)
    };
    w.inactive.bg_stroke = Stroke::new(1.0, control_border);
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.7));
    w.hovered.fg_stroke = Stroke::new(1.5, p.text);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.5, p.text);
}

pub fn install_style(ctx: &egui::Context) {
    ctx.style_mut_of(Theme::Dark, |s| style_for(s, true));
    ctx.style_mut_of(Theme::Light, |s| style_for(s, false));
}

/// A 64×64 window icon drawn in code: an accent disc with clock hands.
pub fn window_icon() -> egui::IconData {
    const N: u32 = 64;
    let c = (N as f32 - 1.0) / 2.0;
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    // Hands as segments from the centre: (angle from 12 o'clock in degrees, length, half-width).
    let hands = [(300.0f32, 17.0f32, 2.6f32), (60.0, 23.0, 2.0)];
    for y in 0..N {
        for x in 0..N {
            let (dx, dy) = (x as f32 - c, y as f32 - c);
            let d = (dx * dx + dy * dy).sqrt();
            let disc = (30.5 - d).clamp(0.0, 1.0);
            if disc <= 0.0 {
                continue;
            }
            let mut white = 0.0f32;
            for (deg, len, hw) in hands {
                let a = deg.to_radians();
                let (ux, uy) = (a.sin(), -a.cos());
                let t = (dx * ux + dy * uy).clamp(0.0, len);
                let (px, py) = (dx - ux * t, dy - uy * t);
                let dist = (px * px + py * py).sqrt();
                white = white.max((hw + 0.5 - dist).clamp(0.0, 1.0));
            }
            white = white.max((4.0 - d).clamp(0.0, 1.0));
            // Tick marks at 12, 3, 6, 9.
            for (tx, ty) in [(0.0, -1.0), (1.0, 0.0), (0.0, 1.0), (-1.0f32, 0.0f32)] {
                let along = dx * tx + dy * ty;
                let across = (dx * ty - dy * tx).abs();
                if (21.0..27.0).contains(&along) {
                    white = white.max((2.0 - across).clamp(0.0, 1.0));
                }
            }
            let i = ((y * N + x) * 4) as usize;
            let mix = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * white).round() as u8;
            rgba[i] = mix(ACCENT.r(), 255);
            rgba[i + 1] = mix(ACCENT.g(), 255);
            rgba[i + 2] = mix(ACCENT.b(), 255);
            rgba[i + 3] = (disc * 255.0) as u8;
        }
    }
    egui::IconData {
        rgba,
        width: N,
        height: N,
    }
}
