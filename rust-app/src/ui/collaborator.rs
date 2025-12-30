use eframe::egui::{self, Color32};
use crate::app::VantaApp;
use egui_extras::{TableBuilder, Column};

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("📡 VantaCollaborator (OAST)");
    ui.label("Catch out-of-band interactions (Blind XSS, SSRF, RCE).");
    ui.separator();
    
    ui.horizontal(|ui| {
        ui.label("Port:");
        ui.text_edit_singleline(&mut app.collab_port);
        
        if app.collab_running {
            if ui.button("⏹ Stop Server").clicked() {
                // Stopping logic is complex with simple spawn. For MVP we might just set flag and let user know restart needed?
                // Or better: Use abort handle. But for now simplest is just "Running" indicator.
                // We can't easily kill the tokio task without handle.
                // Let's just disable the UI feedback for now.
                app.collab_running = false; 
                app.logs.push("Collaborator stopped (Server task might still be listening till app restart).".into());
            }
            ui.colored_label(Color32::GREEN, "● Listening");
        } else {
             if ui.button("▶ Start Server").clicked() {
                 if let Ok(port) = app.collab_port.parse::<u16>() {
                     // Start Server
                     app.collab_running = true;
                     let tx = app.tx_collab.clone();
                     
                     tokio::spawn(async move {
                         crate::core::collaborator::start_collaborator_server(port, tx).await;
                     });
                     
                     app.logs.push(format!("Collaborator started on port {}.", port));
                 } else {
                     app.logs.push("Invalid port.".into());
                 }
             }
        }
    });

    if app.collab_running {
         ui.horizontal(|ui| {
             // Basic IP detection is hard locally, suggest 127.0.0.1 or 0.0.0.0
             ui.label(format!("Payload Base: http://LOCAL_IP:{}/", app.collab_port));
             if ui.button("📋 Copy Random Payload").clicked() {
                 let uuid = uuid::Uuid::new_v4().to_string();
                 let payload = format!("http://127.0.0.1:{}/{}", app.collab_port, uuid);
                 ui.output_mut(|o| o.copied_text = payload);
             }
         });
    }

    ui.separator();
    ui.heading(format!("Interactions ({})", app.collab_interactions.len()));

    TableBuilder::new(ui)
        .column(Column::initial(80.0)) // Time
        .column(Column::initial(120.0)) // Source IP
        .column(Column::initial(150.0)) // Method & Path
        .column(Column::remainder()) // Data/Query
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("Time"); });
            header.col(|ui| { ui.strong("Source IP"); });
            header.col(|ui| { ui.strong("Request"); });
            header.col(|ui| { ui.strong("Data"); });
        })
        .body(|mut body| {
            for interaction in &app.collab_interactions {
                 body.row(18.0, |mut row| {
                     row.col(|ui| { ui.label(&interaction.timestamp); });
                     row.col(|ui| { ui.label(&interaction.src_ip); });
                     row.col(|ui| { ui.label(format!("{} {}", interaction.method, interaction.path)); });
                     row.col(|ui| { ui.label(format!("{} {}", interaction.query, interaction.body)); });
                 });
            }
        });
}
