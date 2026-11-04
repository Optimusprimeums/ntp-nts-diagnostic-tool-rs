// Windowed application on Windows: no console window behind the GUI.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod gui;
mod theme;

fn main() -> eframe::Result {
    gui::run()
}
