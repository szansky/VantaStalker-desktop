use eframe::egui::{self, Color32};
use crate::app::VantaApp;
use crate::core::jwt;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🔐 JWT Analyzer");
    ui.label("Decode, Inspect, and Attack JSON Web Tokens.");
    ui.separator();

    ui.columns(2, |columns| {
        // Left Column: Input
        columns[0].vertical(|ui| {
            ui.label("Encoded Token:");
            if ui.add(egui::TextEdit::multiline(&mut app.jwt_input).font(egui::TextStyle::Monospace).desired_rows(5)).changed() {
                // Auto-decode on change
                app.jwt_parsed = jwt::decode(app.jwt_input.trim());
            }

            ui.add_space(10.0);
            ui.label("Actions:");
            if ui.button("⚠️ Attack: Alg None").clicked() {
                let attacked = jwt::attack_none_alg(app.jwt_input.trim());
                app.jwt_input = attacked;
                app.jwt_parsed = jwt::decode(&app.jwt_input);
            }
        });

        // Right Column: Output
        columns[1].vertical(|ui| {
            ui.label("Decoded:");
            
            if !app.jwt_parsed.valid_structure {
                ui.colored_label(Color32::RED, "Invalid JWT Structure (Expected 3 parts)");
            } else {
                 ui.label(egui::RichText::new("Header").strong());
                 ui.add(egui::TextEdit::multiline(&mut app.jwt_parsed.header)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(3)
                    .code_editor()); // Read-only view essentially
                 
                 ui.add_space(5.0);
                 ui.label(egui::RichText::new("Payload").strong());
                 ui.add(egui::TextEdit::multiline(&mut app.jwt_parsed.payload)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(10)
                    .code_editor());

                 ui.add_space(5.0);
                 ui.label(egui::RichText::new("Signature").strong());
                 ui.add(egui::TextEdit::multiline(&mut app.jwt_parsed.signature)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(2));
                 
                 if let Some(header) = &app.jwt_parsed.header_parsed {
                     if header.alg.to_lowercase() == "none" {
                         ui.colored_label(Color32::RED, "⚠️ Algorithm is NONE (Insecure!)");
                     } else {
                         ui.colored_label(Color32::GREEN, format!("Algorithm: {}", header.alg));
                     }
                 }
            }
        });
    });
}
