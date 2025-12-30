use eframe::egui;
use crate::app::VantaApp;
use crate::core::models::AsyncPortScanJob;
use egui_extras::{TableBuilder, Column};

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🔌 Port Scanner");
    ui.label("Scan open ports on a target host. Detects common services.");
    ui.separator();
    
    ui.horizontal(|ui| {
        ui.label("Target Host/IP:");
        ui.text_edit_singleline(&mut app.portscan_target);
    });
    ui.horizontal(|ui| {
        ui.label("Ports (comma separated, e.g. 80,443,8080):");
        ui.text_edit_singleline(&mut app.portscan_port_range);
    });
    
    if app.portscan_running {
        ui.spinner();
        ui.label("Scanning...");
    } else {
        if ui.button("🚀 Start Scan").clicked() {
            app.portscan_running = true;
            app.portscan_results.clear();
            
            let target = app.portscan_target.clone();
            let ports: Vec<u16> = app.portscan_port_range.split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
            
            if ports.is_empty() {
                app.logs.push("[PortScan] No valid ports specified.".into());
                app.portscan_running = false;
            } else {
                let _ = app.tx_portscan_job.send(AsyncPortScanJob { target, ports });
                app.logs.push("[PortScan] Started scan...".into());
            }
        }
    }
    
    ui.separator();
    ui.heading(format!("Open Ports ({})", app.portscan_results.len()));
    
    TableBuilder::new(ui)
        .column(Column::initial(100.0))
        .column(Column::remainder())
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("Port"); });
            header.col(|ui| { ui.strong("Service"); });
        })
        .body(|mut body| {
            for (port, service) in &app.portscan_results {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.label(port.to_string()); });
                    row.col(|ui| { ui.label(service); });
                });
            }
        });
}
