use eframe::egui;

mod core;
mod ui;
mod app;

use app::VantaApp;

fn main() -> eframe::Result<()> {
    // Run the native GUI
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 720.0])
            .with_title("VantaStalker Pro"),
        ..Default::default()
    };
    
    eframe::run_native(
        "VantaStalker",
        native_options,
        Box::new(|cc| Ok(Box::new(VantaApp::new(cc)))),
    )
}
