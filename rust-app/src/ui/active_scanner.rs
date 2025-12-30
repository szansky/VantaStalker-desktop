use eframe::egui::{self, Color32};
use crate::app::VantaApp;
use crate::core::models::AsyncActiveScanJob;
use egui_extras::{TableBuilder, Column};

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🤖 Active Scanner");
    ui.label("Automatically test for SQL Injection, XSS, Command Injection, and SSRF.");
    ui.separator();
    
    ui.horizontal(|ui| {
        ui.label("Target URL with params:");
        ui.text_edit_singleline(&mut app.activescan_target_url);
    });
    
    ui.horizontal(|ui| {
        if app.activescan_running {
            ui.spinner();
            ui.label(format!("Scanning... {} findings", app.activescan_findings.len()));
        } else {
            if ui.button("🚀 Start Scan").clicked() {
                if let Ok(url) = url::Url::parse(&app.activescan_target_url) {
                    app.activescan_running = true;
                    app.activescan_findings.clear();
                    app.activescan_tested = 0;
                    app.jobs_active = 0; 
                    
                    let mut jobs_count = 0;
                    for (param, value) in url.query_pairs() {
                        let job = AsyncActiveScanJob {
                            url: app.activescan_target_url.clone(), 
                            param: param.to_string(),
                            original_value: value.to_string(),
                        };
                        let _ = app.tx_activescan_job.send(job);
                        jobs_count += 1;
                    } 
                    app.logs.push(format!("[Scanner] Started active scan on {} parameters.", jobs_count));
                } else {
                    app.logs.push("[Scanner] Invalid URL.".into());
                }
            }
        }
        
        if ui.button("📄 Export Report").clicked() {
            if let Some(path) = rfd::FileDialog::new().add_filter("HTML", &["html"]).save_file() {
                let report = crate::core::reporting::generate_html_report(&app.activescan_findings);
                if let Err(e) = std::fs::write(path, report) {
                    app.logs.push(format!("Failed to save report: {}", e));
                } else {
                     app.logs.push("Report saved successfully.".to_string());
                }
            }
        }
    });
    
    ui.separator();
    ui.heading("Vulnerability Findings");
    
    TableBuilder::new(ui)
        .column(Column::initial(80.0)) // Severity
        .column(Column::initial(100.0)) // Type
        .column(Column::initial(100.0)) // Param
        .column(Column::remainder()) // Payload
        .header(20.0, |mut header| {
            header.col(|ui| { ui.strong("Severity"); });
            header.col(|ui| { ui.strong("Type"); });
            header.col(|ui| { ui.strong("Param"); });
            header.col(|ui| { ui.strong("Payload"); });
        })
        .body(|mut body| {
            for finding in &app.activescan_findings {
                body.row(18.0, |mut row| {
                    row.col(|ui| { 
                        let color = match finding.severity.as_str() {
                            "High" => Color32::RED,
                            "Medium" => Color32::ORANGE,
                            _ => Color32::YELLOW,
                        };
                        ui.colored_label(color, &finding.severity); 
                    });
                    row.col(|ui| { ui.label(&finding.vuln_type); });
                    row.col(|ui| { ui.label(&finding.param); });
                    row.col(|ui| { ui.label(&finding.payload); });
                });
            }
        });
}
