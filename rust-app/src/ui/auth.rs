use eframe::egui;
use crate::app::VantaApp;


pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🔐 Authentication Helper");
    ui.separator();

    let profile = &mut app.auth_profile;

    ui.horizontal(|ui| {
        ui.checkbox(&mut profile.enabled, "Enable Auto-Login");
        if profile.enabled {
            ui.label("✅ Active");
        } else {
            ui.label("❌ Disabled");
        }
    });

    ui.separator();
    
    ui.collapsing("⚡ Smart Setup (Auto-Discovery)", |ui| {
        ui.label("Enter your login credentials and we will attempt to auto-configure the Auth Profile.");
        egui::Grid::new("smart_setup_grid").num_columns(2).spacing([40.0, 10.0]).show(ui, |ui| {
             ui.label("Login Page URL:");
             ui.text_edit_singleline(&mut profile.login_url); 
             ui.end_row();

             ui.label("Username:");
             ui.text_edit_singleline(&mut profile.target_username);
             ui.end_row();

             ui.label("Password:");
             ui.add(egui::TextEdit::singleline(&mut profile.target_password).password(true));
             ui.end_row();
        });
        if ui.button("🚀 Auto-Detect & Configure").clicked() {
             app.logs.push(format!("🕵️ Scanning {} for login forms...", profile.login_url));
             
             let url = profile.login_url.clone();
             let user = profile.target_username.clone();
             let pass = profile.target_password.clone();
             let tx = app.tx_auth_probe.clone();

             // Async Task
             tokio::spawn(async move {
                  if let Some(config) = crate::core::auth_prober::probe_login_form(&url, &user, &pass).await {
                      let _ = tx.send(config);
                  } else {
                      // We might want to send a "Failed" signal to log, but for now silent fail or check logs
                  }
             });
        }
    });

    ui.separator();

    egui::Grid::new("auth_config_grid")
        .num_columns(2)
        .spacing([40.0, 10.0])
        .striped(true)
        .show(ui, |ui| {
            // Trigger Section
            ui.label("Trigger Status Codes:");
            ui.horizontal(|ui| {
                // Parse Vec<u16> to String for editing (simplified)
                let mut status_str = profile.trigger_status_codes.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
                if ui.text_edit_singleline(&mut status_str).changed() {
                    profile.trigger_status_codes = status_str.split(',')
                        .filter_map(|s| s.trim().parse::<u16>().ok())
                        .collect();
                }
                ui.label("(comma separated, e.g. 401, 403)");
            });
            ui.end_row();

            ui.label("Trigger Body Match:");
            ui.text_edit_singleline(&mut profile.trigger_body_match);
            ui.end_row();

            // Login Request Section
            ui.label("Login URL:");
            ui.text_edit_singleline(&mut profile.login_url);
            ui.end_row();

            ui.label("Login Method:");
            egui::ComboBox::from_id_salt("login_method")
                .selected_text(&profile.login_method)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut profile.login_method, "POST".to_string(), "POST");
                    ui.selectable_value(&mut profile.login_method, "GET".to_string(), "GET");
                });
            ui.end_row();
            
            ui.label("Login Body:");
             ui.add(egui::TextEdit::multiline(&mut profile.login_body).desired_rows(3));
            ui.end_row();

            // Token Extraction Section
            ui.label("Token Regex:");
            ui.text_edit_singleline(&mut profile.token_extraction_regex);
            ui.end_row();

            ui.label("Target Header:");
            ui.text_edit_singleline(&mut profile.token_dest_header);
            ui.end_row();

            ui.label("Header Format:");
            ui.text_edit_singleline(&mut profile.token_format);
            ui.end_row();
        });

    ui.separator();
    ui.label("📝 Notes:");
    ui.label("1. Define the status code that indicates an expired session (usually 401).");
    ui.label("2. Configure the Login Request that successfully obtains a new token.");
    ui.label("3. Use Regex to extract the token from the login response.");
    ui.label("   Example: \"token\":\"(.*?)\"");
    ui.label("4. The extracted token will be inserted into the Target Header using the format.");
    ui.label("   Example: Authorization: Bearer <token>");
}
