use eframe::egui::{self, Color32, RichText};
use crate::app::VantaApp;
use crate::core::diffing::compute_diff;
use similar::ChangeTag;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🧬 Diffing (Response Comparator)");

    ui.columns(2, |columns| {
        columns[0].vertical(|ui| {
            ui.label("Input A (Original)");
            ui.text_edit_multiline(&mut app.diff_input_a);
        });
        columns[1].vertical(|ui| {
            ui.label("Input B (Modified)");
            ui.text_edit_multiline(&mut app.diff_input_b);
        });
    });

    ui.separator();
    ui.heading("Diff Output");
    
    // Compute diff on the fly? Or button? 
    // Button is safer for large texts.
    if ui.button("Compare").clicked() {
        app.diff_result = compute_diff(&app.diff_input_a, &app.diff_input_b);
    }

    if !app.diff_result.is_empty() {
        egui::ScrollArea::vertical().show(ui, |ui| {
            for line in &app.diff_result {
                let (color, prefix) = match line.tag {
                    ChangeTag::Equal => (ui.visuals().text_color(), "  "),
                    ChangeTag::Delete => (Color32::RED, "- "),
                    ChangeTag::Insert => (Color32::GREEN, "+ "),
                };
                
                // We can use a colored background for better visibility, but text color is simpler for now.
                // For deletions, maybe strike-through or red background is better.
                // RichText allows background color in newer egui? 
                // Let's stick to colored text.
                
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("{}{}", prefix, line.content.trim_end())).color(color).family(egui::FontFamily::Monospace));
                });
            }
        });
    }
}
