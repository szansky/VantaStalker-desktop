use eframe::egui;
use rfd::FileDialog;
use crate::app::VantaApp;
use crate::core::models::{AsyncIntruderJob, IntruderMode, PayloadTransform, NodeCommand};
use egui_extras::{TableBuilder, Column};
use base64::prelude::*;
use md5::Md5;
use md5::Digest; // Added Digest trait
use rayon::prelude::*; // Need Rayon traits

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.columns(2, |columns| {
        columns[0].vertical(|ui| {
            ui.heading("Attack Configuration");
            ui.label("Target URL:");
            ui.text_edit_singleline(&mut app.intr_url);
            
            ui.label("Body Template (Use §payload§ marker):");
            ui.text_edit_multiline(&mut app.intr_body_template);

            ui.horizontal(|ui| {
                ui.label("Attack Type:");
                egui::ComboBox::from_id_salt("intr_attack_mode").selected_text(format!("{:?}", app.intr_attack_mode)).show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.intr_attack_mode, crate::core::models::AttackMode::Sniper, "Sniper (1 Set)");
                    ui.selectable_value(&mut app.intr_attack_mode, crate::core::models::AttackMode::Pitchfork, "Pitchfork (1-to-1)");
                    ui.selectable_value(&mut app.intr_attack_mode, crate::core::models::AttackMode::ClusterBomb, "Cluster Bomb (N x M)");
                });
            });

            ui.add_space(5.0);
            
            // Set 1
            ui.horizontal(|ui| {
                ui.strong("Payload Set 1:");
                if ui.button("📂 Load...").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        if let Ok(content) = std::fs::read_to_string(path) {
                            app.intr_payloads = content;
                        }
                    }
                }
            });
            ui.text_edit_multiline(&mut app.intr_payloads);

            // Set 2 (Conditional)
            if app.intr_attack_mode != crate::core::models::AttackMode::Sniper {
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.strong("Payload Set 2:");
                    if ui.button("📂 Load...").clicked() {
                        if let Some(path) = FileDialog::new().pick_file() {
                            if let Ok(content) = std::fs::read_to_string(path) {
                                app.intr_payloads_2 = content;
                            }
                        }
                    }
                });
                ui.text_edit_multiline(&mut app.intr_payloads_2);
            }
            
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.label("Transformation:");
                egui::ComboBox::from_id_salt("intr_transform").selected_text(format!("{:?}", app.intr_transform)).show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.intr_transform, PayloadTransform::Identity, "Identity");
                    ui.selectable_value(&mut app.intr_transform, PayloadTransform::Base64, "Base64");
                    ui.selectable_value(&mut app.intr_transform, PayloadTransform::MD5, "MD5");
                });
            });
                
            ui.horizontal(|ui| {
                ui.label("Engine:");
                egui::ComboBox::from_id_salt("intr_mode").selected_text(format!("{:?}", app.intr_mode)).show_ui(ui, |ui| {
                    ui.selectable_value(&mut app.intr_mode, IntruderMode::Native, "Native (Fast, no JS)");
                    ui.selectable_value(&mut app.intr_mode, IntruderMode::Browser, "Browser (Slow, full JS)");
                });
            });

            if !app.intr_running {
                if ui.button("🔥 Start Attack").clicked() {
                    app.intr_running = true;
                    app.intr_current_idx = 0;
                    app.intr_results.clear();
                    
                    let mut raw_sets = vec![];
                    
                    // Set 1
                    raw_sets.push(app.intr_payloads.lines().map(|s| s.to_string()).collect::<Vec<String>>());
                    
                    // Set 2
                    if app.intr_attack_mode != crate::core::models::AttackMode::Sniper {
                         raw_sets.push(app.intr_payloads_2.lines().map(|s| s.to_string()).collect::<Vec<String>>());
                    }

                    // Apply Transformations to all sets
                    // Note: Parallel iter on outer vec is tricky with mutable ref, so we iterate sets then par_iter inner
                    for payloads in &mut raw_sets {
                        match app.intr_transform {
                            PayloadTransform::Identity => {},
                            PayloadTransform::Base64 => {
                                 payloads.par_iter_mut().for_each(|p| {
                                     *p = BASE64_STANDARD.encode(p.as_bytes());
                                 });
                            },
                            PayloadTransform::MD5 => {
                                 payloads.par_iter_mut().for_each(|p| {
                                     let mut hasher = Md5::new();
                                     hasher.update(p.as_bytes());
                                     let result = hasher.finalize();
                                     *p = result.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                                 });
                            }
                        }
                    }

                    if app.intr_mode == IntruderMode::Native {
                        // NATIVE MODE
                         let job = AsyncIntruderJob {
                            url: app.intr_url.clone(),
                            method: app.intr_method.clone(),
                            headers: app.intr_headers.clone().into_iter().collect(), // Convert BTreeMap to Vec
                            body_template: app.intr_body_template.clone(),
                            payload_sets: raw_sets.clone(),
                            attack_mode: app.intr_attack_mode,
                         };
                         let _ = app.tx_intruder_job.send(job);
                         app.logs.push(format!("Started Native Intruder ({:?})", app.intr_attack_mode));

                    } else {
                        // BROWSER MODE (Legacy) - Warn user it only supports Sniper / Set 1 for now
                         let payloads = &raw_sets[0]; 
                         for (i, payload) in payloads.iter().enumerate() {
                            let mut map = serde_json::Map::new();
                            for (k, v) in &app.intr_headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
                            let body = if app.intr_body_template.contains("§payload§") {
                                Some(app.intr_body_template.replace("§payload§", payload))
                            } else {
                                None 
                            };
                            let _ = app.tx_command.send(NodeCommand::SendRequest { id: 1000 + i as u32, method: app.intr_method.clone(), url: app.intr_url.clone(), headers: serde_json::Value::Object(map), body });
                        }
                        app.logs.push(format!("Queued {} browser requests (Sniper fallback)", payloads.len()));
                    }
                }
            } else {
                ui.spinner();
                if ui.button("⏹ Stop").clicked() {
                    app.intr_running = false;
                }
            }
        });
        
        columns[1].vertical(|ui| {
            ui.heading("Results");
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::auto())
                .column(Column::auto())
                .column(Column::remainder()) // Payload
                .header(20.0, |mut header| {
                    header.col(|ui| { ui.strong("Status"); });
                    header.col(|ui| { ui.strong("Length"); });
                    header.col(|ui| { ui.strong("Payload"); });
                })
                .body(|mut body| {
                    for res in &app.intr_results {
                        body.row(18.0, |mut row| {
                            row.col(|ui| { ui.label(res.status.to_string()); });
                            row.col(|ui| { ui.label(res.length.to_string()); });
                            row.col(|ui| { ui.label(&res.payload); });
                        });
                    }
                });
        });
    });
}
