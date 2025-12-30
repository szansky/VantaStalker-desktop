use eframe::egui;
use crate::app::VantaApp;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🎯 Scope Configuration");
    ui.label("Define a list of domains. Interceptor will only stop requests that contain these strings.");
    ui.horizontal(|ui| {
        ui.label("Add Domain:");
        ui.text_edit_singleline(&mut app.new_scope_domain);
        if ui.button("Add").clicked() && !app.new_scope_domain.is_empty() {
            app.scope_domains.push(app.new_scope_domain.clone());
            app.new_scope_domain.clear();
        }
    });
     egui::ScrollArea::vertical().show(ui, |ui| {
        let mut remove_idx = None;
        for (i, domain) in app.scope_domains.iter().enumerate() {
            ui.horizontal(|ui| { ui.label(format!("• {}", domain)); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
        }
        if let Some(i) = remove_idx { app.scope_domains.remove(i); }
    });
}
