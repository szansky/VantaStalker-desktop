use eframe::egui::{self, Color32};
use egui_plot::{Plot, Bar, BarChart};
use crate::app::VantaApp;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("📊 Security Dashboard");
    
    // Top Stats Row
    ui.horizontal(|ui| {
        let card = |ui: &mut egui::Ui, title: &str, value: String, color: Color32| {
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    ui.label(title);
                    ui.heading(egui::RichText::new(value).color(color).strong());
                });
            });
        };
        
        card(ui, "Total Requests", app.history.len().to_string(), Color32::LIGHT_BLUE);
        card(ui, "Pending Queue", app.queue.len().to_string(), Color32::YELLOW);
        let vuln_count: usize = app.scanner_findings.iter().count() + app.activescan_findings.len();
        card(ui, "Vulnerabilities", vuln_count.to_string(), if vuln_count > 0 { Color32::RED } else { Color32::GREEN });
        let subdomains_count = app.recon_results.len();
        card(ui, "Subdomains", subdomains_count.to_string(), Color32::LIGHT_GREEN);
        let open_ports_count = app.portscan_results.len();
        card(ui, "Open Ports", open_ports_count.to_string(), Color32::ORANGE);
    });
    
    ui.add_space(20.0);
    ui.separator();
    
    // Charts Row
    ui.columns(2, |columns| {
        columns[0].group(|ui| {
            ui.heading("Status Code Distribution");
            let mut status_2xx = 0;
            let mut status_3xx = 0;
            let mut status_4xx = 0;
            let mut status_5xx = 0;

            for item in &app.history {
                if item.status.starts_with("2") { status_2xx += 1; }
                else if item.status.starts_with("3") { status_3xx += 1; }
                else if item.status.starts_with("4") { status_4xx += 1; }
                else if item.status.starts_with("5") { status_5xx += 1; }
            }
            
            // Bar chart using egui_plot
            
            let bars = vec![
                Bar::new(0.0, status_2xx as f64).name("2xx Success").fill(egui::Color32::GREEN),
                Bar::new(1.0, status_3xx as f64).name("3xx Redirect").fill(egui::Color32::YELLOW),
                Bar::new(2.0, status_4xx as f64).name("4xx Client Error").fill(egui::Color32::from_rgb(255, 165, 0)),
                Bar::new(3.0, status_5xx as f64).name("5xx Server Error").fill(egui::Color32::RED),
            ];
            
            let chart = BarChart::new(bars).width(0.7);
            
            Plot::new("status_chart")
                .height(200.0)
                .allow_drag(false)
                .allow_zoom(false)
                .show_axes([false, true])
                .show(ui, |plot_ui| {
                    plot_ui.bar_chart(chart);
                });
            
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::GREEN, format!("2xx: {}", status_2xx));
                ui.colored_label(egui::Color32::YELLOW, format!("3xx: {}", status_3xx));
                ui.colored_label(egui::Color32::from_rgb(255, 165, 0), format!("4xx: {}", status_4xx));
                ui.colored_label(egui::Color32::RED, format!("5xx: {}", status_5xx));
            });
        });

        columns[1].group(|ui| {
             // Recent Activity Log from Dashboard
            ui.heading("Recent Activity");
            egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                for log in app.logs.iter().rev().take(15) {
                    ui.label(log);
                }
            });
        });
    });
}
