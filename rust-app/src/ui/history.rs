use eframe::egui;
use egui_extras::{TableBuilder, Column}; // Keep, used in function
use rfd::FileDialog;
use crate::app::VantaApp;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    
    ui.horizontal(|ui| {
        ui.heading("📜 Request History");
        ui.separator();
        
        if ui.button("📤 Export CSV").clicked() {
            if let Some(path) = FileDialog::new()
                .add_filter("CSV", &["csv"])
                .set_file_name("history.csv")
                .save_file() 
            {
                let mut csv = String::from("ID,Method,URL,Status\n");
                for item in &app.history {
                    csv.push_str(&format!("{},{},{},{}\n", 
                        item.id, item.method, item.url, item.status));
                }
                if std::fs::write(&path, csv).is_ok() {
                    app.logs.push(format!("[Export] Saved {} items to CSV", app.history.len()));
                }
            }
        }
        
        if ui.button("📤 Export JSON").clicked() {
            if let Some(path) = FileDialog::new()
                .add_filter("JSON", &["json"])
                .set_file_name("history.json")
                .save_file() 
            {
                if let Ok(json) = serde_json::to_string_pretty(&app.history) {
                    if std::fs::write(&path, json).is_ok() {
                        app.logs.push(format!("[Export] Saved {} items to JSON", app.history.len()));
                    }
                }
            }
        }
        
        ui.label(format!("{} requests", app.history.len()));
    });
    
    ui.separator();
    
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().resizable(true)) // ID
        .column(Column::auto().resizable(true)) // Method
        .column(Column::remainder())            // URL (takes rest of space)
        .column(Column::auto().resizable(true)) // Status
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("ID"); });
            header.col(|ui| { ui.strong("Method"); });
            header.col(|ui| { ui.strong("URL"); });
            header.col(|ui| { ui.strong("Status"); });
        })
        .body(|mut body| {
            for item in &app.history {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.label(item.id.to_string()); });
                    row.col(|ui| { ui.label(&item.method); });
                    row.col(|ui| { ui.label(&item.url); }); // Too long URLs might need truncation or scroll
                    row.col(|ui| { 
                            // Status color coding
                        let color = if item.status.starts_with("2") { egui::Color32::GREEN } 
                                    else if item.status.starts_with("3") { egui::Color32::YELLOW }
                                    else if item.status.starts_with("4") || item.status.starts_with("5") { egui::Color32::RED }
                                    else { egui::Color32::GRAY };
                        ui.colored_label(color, &item.status);
                    });
                });
            }
        });
}
