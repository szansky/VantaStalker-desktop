use eframe::egui;
use crate::app::VantaApp;
use crate::core::models::AsyncReconJob;
use egui_extras::{TableBuilder, Column};
use rfd::FileDialog;
use eframe::egui::Color32;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("📡 DNS Subdomain Enumeration");
    ui.label("Brute-force subdomains using a wordlist.");
    ui.separator();
    
    ui.horizontal(|ui| {
        ui.label("Root Domain (e.g. google.com):");
        ui.text_edit_singleline(&mut app.recon_domain);
    });
    
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("Wordlist (One per line):");
                if ui.button("📂 Load Wordlist...").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        if let Ok(content) = std::fs::read_to_string(path) {
                            app.recon_wordlist = content;
                        }
                    }
                }
                if ui.button("🚀 Start Recon").clicked() && !app.recon_running {
                    app.recon_running = true;
                    app.recon_results.clear();
                    
                    let domain = app.recon_domain.clone();
                    // Split wordlist
                    let wordlist: Vec<String> = app.recon_wordlist.lines().map(|s| s.to_string()).collect();

                    let _ = app.tx_recon_job.send(AsyncReconJob { domain, wordlist });
                    app.logs.push("[Recon] Started DNS enumeration...".into());
                }
        });
        ui.text_edit_multiline(&mut app.recon_wordlist);
        
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading(format!("Results ({})", app.recon_results.len()));
            if ui.button("📤 Export TXT").clicked() {
                if let Some(path) = FileDialog::new()
                    .add_filter("TXT", &["txt"])
                    .set_file_name("subdomains.txt")
                    .save_file() 
                {
                    let content = app.recon_results.iter().map(|(d, ip)| format!("{} - {}", d, ip)).collect::<Vec<_>>().join("\n");
                    if std::fs::write(&path, content).is_ok() {
                        app.logs.push(format!("[Export] Saved {} subdomains to TXT", app.recon_results.len()));
                    }
                }
            }
        });
        
        TableBuilder::new(ui)
            .column(Column::initial(300.0).resizable(true))
            .column(Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| { ui.strong("Subdomain"); });
                header.col(|ui| { ui.strong("IP Address"); });
            })
            .body(|mut body| {
                for (sub, ip) in &app.recon_results {
                    body.row(18.0, |mut row| {
                        row.col(|ui| { ui.label(sub); });
                        row.col(|ui| { ui.label(ip); });
                    });
                }
    });
    
    ui.add_space(20.0);
    ui.heading("📂 Directory Fuzzer");
    ui.label("Find hidden files and directories.");
    ui.separator();
    
    ui.group(|ui| {
         ui.horizontal(|ui| {
            ui.label("Target URL:");
            ui.text_edit_singleline(&mut app.fuzzer_url);
            
            if ui.button("🚀 Start Fuzzing").clicked() && !app.fuzzer_running {
                 app.fuzzer_running = true;
                 app.fuzzer_results.clear();
                 
                 let target = app.fuzzer_url.clone();
                 let wordlist: Vec<String> = app.fuzzer_wordlist.lines().map(|s| s.to_string()).collect();
                 
                 // Spawn task
                 // NOTE: Since we can't easily clone channel sender from App into UI easily without proper setup, 
                 // we'll spawn here or use a command channel.
                 // For MVP, we will assume app.rs handles spawning via a channel or just spawn here if we have a sender.
                 // But wait, tx_fuzzer_res is in app.new() only? No, we need it in the struct to clone it.
                 // I defined tx_fuzzer as Option<Sender<(Url, Wordlist)>> in app.rs, let's use that pattern (Worker).
                 
                 if let Some(tx) = &app.tx_fuzzer {
                     let tx = tx.clone();
                     tokio::spawn(async move {
                         let _ = tx.send((target, wordlist)).await;
                     });
                 }
                 app.logs.push("[Fuzzer] Started directory scan...".into());
            }
         });
         
         ui.horizontal(|ui| {
             ui.label("Wordlist:");
             ui.text_edit_multiline(&mut app.fuzzer_wordlist);
         });

         ui.separator();
         ui.heading(format!("Results ({})", app.fuzzer_results.len()));
         
         TableBuilder::new(ui)
            .column(Column::initial(60.0).resizable(true)) // Status
            .column(Column::initial(80.0).resizable(true)) // Length
            .column(Column::remainder()) // URL
            .header(20.0, |mut header| {
                header.col(|ui| { ui.strong("Status"); });
                header.col(|ui| { ui.strong("Length"); });
                header.col(|ui| { ui.strong("URL"); });
            })
            .body(|mut body| {
                for res in &app.fuzzer_results {
                    body.row(18.0, |mut row| {
                        row.col(|ui| { 
                            let color = if res.status == 200 { Color32::GREEN } else { Color32::YELLOW };
                            ui.colored_label(color, res.status.to_string()); 
                        });
                        row.col(|ui| { ui.label(res.length.to_string()); });
                        row.col(|ui| { ui.label(&res.url); });
                    });
                }
            });
            });
    });

    ui.add_space(20.0);
    ui.heading("🔒 SSL/TLS Inspector");
    ui.label("Check certificate validity and details.");
    ui.separator();

    ui.group(|ui| {
         ui.horizontal(|ui| {
            ui.label("Target Host (e.g. google.com):");
            ui.text_edit_singleline(&mut app.ssl_target);
            
            if ui.button("🛡️ Check SSL").clicked() {
                let target = app.ssl_target.clone();
                // This is blocking for now (Command), strictly could be async, but quick enough for MVP usually.
                // For non-blocking UI we should ideally spawn.
                // Let's spawn a quick thread? Eggy updates might be tricky without a channel. 
                // For "Scanner" tools, blocking for 1s is mostly acceptable if simple. 
                // Let's spawn a thread and use a channel if we had one, but we don't for generic tasks easily.
                // Actually, let's just block for MVP stability. `openssl` is fast.
                
                app.ssl_result = crate::core::ssl::check_ssl(&target);
            }
         });
         
         if !app.ssl_result.subject.is_empty() {
             ui.separator();
             ui.strong("Subject:");
             ui.label(&app.ssl_result.subject);
             
             ui.strong("Issuer:");
             ui.label(&app.ssl_result.issuer);
             
             ui.strong("Validity:");
             ui.label(&app.ssl_result.validity);
             
             ui.separator();
             ui.collapsing("Raw Certificate Output", |ui| {
                 ui.code(&app.ssl_result.raw_output);
             });
         }
    });
}
