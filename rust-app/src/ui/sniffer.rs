use eframe::egui;
use crate::app::VantaApp;
use egui_extras::{TableBuilder, Column};

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🦈 Packet Sniffer");
    ui.label("Capture raw network packets. Requires Root/Administrator privileges.");
    ui.separator();
    
    ui.horizontal(|ui| {
        ui.label("Network Interface:");
        // Dropdown for interface selection? For now simple text or predefined list if we had pnet::datalink::interfaces() available here.
        // Since we didn't import pnet here, we rely on the string in app state.
        // Ideally we'd list interfaces. For now let's use the combo box logic from main.rs but simply.
        
        egui::ComboBox::from_id_salt("interface_combo").selected_text(&app.sniffer_interface).show_ui(ui, |ui| {
            ui.selectable_value(&mut app.sniffer_interface, "eth0".to_string(), "eth0");
            ui.selectable_value(&mut app.sniffer_interface, "wlan0".to_string(), "wlan0");
            ui.selectable_value(&mut app.sniffer_interface, "lo".to_string(), "lo");
            ui.selectable_value(&mut app.sniffer_interface, "en0".to_string(), "en0 (Mac)");
        });
        ui.text_edit_singleline(&mut app.sniffer_interface); 
    });
    
    ui.horizontal(|ui| {
        if app.sniffer_running {
            if ui.button("⏹ Stop Capture").clicked() {
                app.sniffer_stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                app.sniffer_running = false;
            }
            ui.spinner();
            ui.label(format!("Capturing... ({} packets)", app.sniffer_packets.len()));
        } else {
            if ui.button("▶ Start Capture").clicked() {
                // We need to spawn the sniffer thread here. 
                // Since moving logic is complex, for this refactor I might need to move start_sniffer into app.rs
                // and call it here.
                // Assuming app has a method `start_sniffer()`, or we implement it here but we need pnet imports.
                // Recommendation: Call app.start_sniffer().
                app.start_sniffer();
            }
        }
        
        if ui.button("🗑 Clear").clicked() {
            app.sniffer_packets.clear();
        }
    });
    
    ui.separator();
    
    TableBuilder::new(ui)
        .striped(true)
        .stick_to_bottom(true)
        .column(Column::auto()) // Time
        .column(Column::auto()) // Src
        .column(Column::auto()) // Dst
        .column(Column::auto()) // Proto
        .column(Column::auto()) // Len
        .column(Column::remainder()) // Info
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("Time"); });
            header.col(|ui| { ui.strong("Source"); });
            header.col(|ui| { ui.strong("Destination"); });
            header.col(|ui| { ui.strong("Protocol"); });
            header.col(|ui| { ui.strong("Length"); });
            header.col(|ui| { ui.strong("Info"); });
        })
        .body(|mut body| {
             // Show last 1000 items (handled by logic in update)
            for pkt in &app.sniffer_packets {
                body.row(18.0, |mut row| {
                    row.col(|ui| { ui.label(&pkt.timestamp); });
                    row.col(|ui| { ui.label(&pkt.src_ip); });
                    row.col(|ui| { ui.label(&pkt.dst_ip); });
                    row.col(|ui| { ui.label(&pkt.protocol); });
                    row.col(|ui| { ui.label(pkt.length.to_string()); });
                    row.col(|ui| { ui.label(&pkt.info); });
                });
            }
        });
}
