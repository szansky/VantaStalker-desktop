use eframe::egui;
use crate::app::VantaApp;
use crate::core::models::NodeCommand;
use crate::ui::syntax;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    // Toolbar
    ui.horizontal(|ui| {
        ui.heading("Repeater");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(if app.view_split_horizontal { "Layout: ↔ Side-by-Side" } else { "Layout: ↕ Top-Bottom" }).clicked() {
                app.view_split_horizontal = !app.view_split_horizontal;
            }
        });
    });
    ui.separator();

    let render_request = |app: &mut VantaApp, ui: &mut egui::Ui| {
        ui.heading("Request");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("rep_method_combo").selected_text(&app.rep_method).show_ui(ui, |ui| {
                ui.selectable_value(&mut app.rep_method, "GET".to_string(), "GET");
                ui.selectable_value(&mut app.rep_method, "POST".to_string(), "POST");
                ui.selectable_value(&mut app.rep_method, "PUT".to_string(), "PUT");
                ui.selectable_value(&mut app.rep_method, "DELETE".to_string(), "DELETE");
            });
            ui.text_edit_singleline(&mut app.rep_url);
        });
        
        ui.label("Headers:");
        egui::ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
            let mut remove_idx = None;
            for (i, (k, v)) in app.rep_headers.iter_mut().enumerate() {
                ui.horizontal(|ui| { ui.text_edit_singleline(k); ui.text_edit_singleline(v); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
            }
            if let Some(i) = remove_idx { app.rep_headers.remove(i); }
            if ui.button("➕ Add Header").clicked() { app.rep_headers.push(("".to_string(), "".to_string())); }
        });

        ui.label("Body:");
        // HEURISTIC: Check if body is JSON
        let lang = if app.rep_body.trim_start().starts_with('{') { "json" } else { "text" };
        
        let mut layouter = |ui: &egui::Ui, string: &str, wrap_width: f32| {
            let mut layout_job = syntax::highlight(ui, string, lang);
            layout_job.wrap.max_width = wrap_width;
            ui.fonts(|f| f.layout_job(layout_job))
        };
        
        ui.add(egui::TextEdit::multiline(&mut app.rep_body)
            .layouter(&mut layouter)
            .code_editor()
            .desired_width(f32::INFINITY)
        );

        if ui.button("▶ Send Request").clicked() { 
            let mut map = serde_json::Map::new();
            for (k, v) in &app.rep_headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
            let _ = app.tx_command.send(NodeCommand::SendRequest { id: 0, method: app.rep_method.clone(), url: app.rep_url.clone(), headers: serde_json::Value::Object(map), body: if app.rep_body.is_empty() { None } else { Some(app.rep_body.clone()) } });
            app.rep_response = "Sending...".into();
        }
    };

    let render_response = |app: &mut VantaApp, ui: &mut egui::Ui| {
        ui.heading("Response");
        
        // HEURISTIC: Response start
        let lang = if app.rep_response.trim_start().starts_with('<') { "html" } 
                   else if app.rep_response.trim_start().starts_with('{') { "json" }
                   else { "text" };

        let mut layouter = |ui: &egui::Ui, string: &str, wrap_width: f32| {
            let mut layout_job = syntax::highlight(ui, string, lang);
            layout_job.wrap.max_width = wrap_width;
            ui.fonts(|f| f.layout_job(layout_job))
        };
        
        ui.add(egui::TextEdit::multiline(&mut app.rep_response)
            .layouter(&mut layouter)
            .code_editor()
            .desired_width(f32::INFINITY)
        );
    };

    if app.view_split_horizontal {
         ui.columns(2, |columns| {
             render_request(app, &mut columns[0]);
             render_response(app, &mut columns[1]);
         });
    } else {
         render_request(app, ui);
         ui.separator();
         render_response(app, ui);
    }
}
