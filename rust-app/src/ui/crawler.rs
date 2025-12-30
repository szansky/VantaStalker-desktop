use eframe::egui::{self, Color32};
use crate::app::VantaApp;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.columns(2, |columns| {
        columns[0].vertical(|ui| {
            ui.heading("🕷 Web Crawler");
            ui.label("Recursively discovery links and map the target website.");
            
            ui.horizontal(|ui| {
                ui.label("Target URL:");
                ui.text_edit_singleline(&mut app.crawl_target);
            });
            
            if app.crawl_active {
                ui.spinner();
                ui.label(format!("Crawling... {} pages discovered.", app.crawl_discovered.len()));
                ui.label(format!("Scanning: {}", app.crawl_current_url));
                if ui.button("⏹ Stop").clicked() {
                    app.crawl_active = false;
                }
            } else {
                if ui.button("🚀 Start Crawl").clicked() {
                    app.crawl_active = true;
                    app.crawl_discovered.clear();
                    app.crawl_queue.clear();
                    app.crawl_results.clear();
                    app.crawl_vulnerabilities.clear();
                    app.crawl_queue.push_back(app.crawl_target.clone());
                    app.logs.push(format!("Started crawling {}", app.crawl_target));
                }
            }
            
            ui.separator();
            ui.heading("Discovered URLs");
            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                for url in &app.crawl_results {
                    ui.label(url);
                }
            });
        });
        
        columns[1].vertical(|ui| {
            ui.heading("Security Report");
            egui::ScrollArea::vertical().max_height(500.0).show(ui, |ui| {
                for vuln in &app.crawl_vulnerabilities {
                    // Simple color coding based on keywords
                    let color = if vuln.contains("[HIGH]") { Color32::RED }
                                else if vuln.contains("[MEDIUM]") { Color32::ORANGE }
                                else { Color32::YELLOW };
                    ui.colored_label(color, vuln);
                }
            });
        });
    });
}
