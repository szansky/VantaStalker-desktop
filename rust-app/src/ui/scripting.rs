use eframe::egui::{self, Color32};
use crate::app::VantaApp;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🧩 Scripting Engine (Rhai)");
    ui.label("Define logic to intercept and modify requests on the fly.");

    ui.horizontal(|ui| {
        if ui.button("▶ Compile & Enable").clicked() {
             match app.script_engine.compile(&app.script_code) {
                 Ok(_) => {
                     app.script_compiled = true;
                     app.script_error = None;
                     app.logs.push("Script compiled successfully.".into());
                 },
                 Err(e) => {
                     app.script_compiled = false;
                     app.script_error = Some(e.clone());
                     app.logs.push(format!("Script Error: {}", e));
                 }
             }
        }
        
        if ui.checkbox(&mut app.script_enabled, "Active").changed() {
            if app.script_enabled && !app.script_compiled {
                app.script_enabled = false; // Prevent enabling if not compiled
            }
        }
    });

    if let Some(err) = &app.script_error {
        ui.label(egui::RichText::new(format!("Error: {}", err)).color(Color32::RED));
    } else if app.script_compiled {
        ui.label(egui::RichText::new("✅ Compiled").color(Color32::GREEN));
    }

    ui.separator();

    ui.add(egui::TextEdit::multiline(&mut app.script_code)
        .font(egui::TextStyle::Monospace)
        .code_editor()
        .desired_width(f32::INFINITY)
        .desired_rows(20)
    );
    
    ui.label("Example:");
    ui.label(r#"
fn on_request(req) {
    print("Intercepted: " + req.url);
    req.headers = req.headers + ", \"X-Hacked\": \"True\"";
    return req;
}
    "#);
}
