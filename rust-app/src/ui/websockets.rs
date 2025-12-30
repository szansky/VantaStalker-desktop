use eframe::egui::{self, Color32};
use crate::app::VantaApp;
use egui_extras::{TableBuilder, Column};
use crate::core::models::WSMessage;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🔌 WebSockets");
    
    // Control Bar
    ui.horizontal(|ui| {
        ui.label("URL:");
        ui.text_edit_singleline(&mut app.ws_url);
        
        if app.ws_connected {
            if ui.button("⏹ Disconnect").clicked() {
                app.ws_connected = false;
                // We don't have a clean disconnect signal here yet for the async task, 
                // but dropping the channel sender/receiver in app might effectively kill it if we re-init?
                // For MVP, setting flag is UI-only usually. 
                // Ideally we'd send a close message via channel.
                // Let's assume re-connect will spawn new.
            }
            ui.colored_label(Color32::GREEN, "● Connected");
        } else {
             if ui.button("▶ Connect").clicked() {
                 app.ws_connected = true;
                 app.ws_history.clear();
                 
                 let (tx_ws_out, rx_ws_out) = tokio::sync::mpsc::unbounded_channel();
                 app.tx_ws_out = Some(tx_ws_out);
                 
                 let url = app.ws_url.clone();
                 let tx_in = app.tx_ws_in.clone();
                 
                 tokio::spawn(async move {
                     crate::core::websockets::connect_and_listen(url, tx_in, rx_ws_out).await;
                 });
             }
        }
    });
    
    ui.separator();

    ui.columns(2, |columns| {
        // Left: History
        columns[0].vertical(|ui| {
            ui.heading(format!("History ({})", app.ws_history.len()));
            TableBuilder::new(ui)
                .column(Column::initial(60.0)) // Time
                .column(Column::initial(40.0)) // Dir
                .column(Column::remainder())   // Content
                .header(20.0, |mut header| {
                    header.col(|ui| { ui.strong("Time"); });
                    header.col(|ui| { ui.strong("Dir"); });
                    header.col(|ui| { ui.strong("Payload"); });
                })
                .body(|mut body| {
                    for item in &app.ws_history {
                        body.row(18.0, |mut row| {
                            row.col(|ui| { ui.label(&item.timestamp); });
                            row.col(|ui| { 
                                if item.direction == "Sent" {
                                    ui.colored_label(Color32::BLUE, "->");
                                } else {
                                    ui.colored_label(Color32::GREEN, "<-");
                                }
                            });
                            row.col(|ui| { 
                                let preview = match &item.message {
                                    WSMessage::Text(t) => t.chars().take(50).collect::<String>(),
                                    WSMessage::Binary(b) => format!("[Binary {} bytes]", b.len()),
                                };
                                ui.label(preview);
                            });
                        });
                    }
                });
        });

        // Right: Sender/Inspector
        columns[1].vertical(|ui| {
            ui.heading("Inspector");
            ui.label("Send Message:");
            ui.text_edit_multiline(&mut app.ws_input);
            
            ui.horizontal(|ui| {
                 if ui.button("Send Text").clicked() {
                     if let Some(tx) = &app.tx_ws_out {
                         let _ = tx.send(WSMessage::Text(app.ws_input.clone()));
                     }
                 }
                 // Binary TBD
            });
        });
    });
}
