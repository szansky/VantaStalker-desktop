use eframe::egui;
use crate::app::VantaApp;
use crate::core::models::{InterceptItem, NodeCommand};

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
     if let Some(item_clone) = app.queue.front().cloned() {
        ui.group(|ui| {
            ui.add_space(5.0);
            match item_clone {
                InterceptItem::Request(ref req) => {
                    ui.heading("🔴 Intercepted Request");
                    ui.label(egui::RichText::new(&req.url).strong());
                    ui.horizontal(|ui| {
                        ui.label("Method:");
                        egui::ComboBox::from_id_salt("method_combo").selected_text(&app.edit_method).show_ui(ui, |ui| {
                            ui.selectable_value(&mut app.edit_method, "GET".to_string(), "GET");
                            ui.selectable_value(&mut app.edit_method, "POST".to_string(), "POST");
                            ui.selectable_value(&mut app.edit_method, "PUT".to_string(), "PUT");
                            ui.selectable_value(&mut app.edit_method, "DELETE".to_string(), "DELETE");
                        });
                    });
                },
                InterceptItem::Response(ref _res) => {
                        ui.heading("🔵 Intercepted Response");
                        ui.horizontal(|ui| { ui.label("New Status:"); ui.text_edit_singleline(&mut app.edit_status); });
                }
            }
            
            ui.label("Headers:");
            egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                let mut remove_idx = None;
                for (i, (k, v)) in app.edit_headers.iter_mut().enumerate() {
                    ui.horizontal(|ui| { ui.text_edit_singleline(k); ui.text_edit_singleline(v); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
                }
                if let Some(i) = remove_idx { app.edit_headers.remove(i); }
                if ui.button("➕ Add Header").clicked() { app.edit_headers.push(("".to_string(), "".to_string())); }
            });

            ui.label("Body:");
            ui.text_edit_multiline(&mut app.edit_body);

            ui.horizontal(|ui| {
                if ui.button("▶ Forward").clicked() {
                        let mut map = serde_json::Map::new();
                    for (k, v) in &app.edit_headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
                    let new_headers = serde_json::Value::Object(map);

                    match item_clone {
                        InterceptItem::Request(ref req) => {
                            let _ = app.tx_command.send(NodeCommand::CONTINUE { id: req.id, method: app.edit_method.clone(), headers: new_headers, body: if app.edit_body.is_empty() { None } else { Some(app.edit_body.clone()) }, intercept_response: app.intercept_responses });
                        },
                        InterceptItem::Response(ref res) => {
                            let status = app.edit_status.parse::<u16>().unwrap_or(res.status);
                            let _ = app.tx_command.send(NodeCommand::FulfillResponse { id: res.id, status, headers: new_headers, body: app.edit_body.clone() });
                        }
                    }
                    app.queue.pop_front();
                    app.editor_loaded_id = None; 
                }
                if ui.button("❌ Drop").clicked() {
                    let id = match item_clone { InterceptItem::Request(ref r) => r.id, InterceptItem::Response(ref r) => r.id };
                    let _ = app.tx_command.send(NodeCommand::DROP { id });
                    app.queue.pop_front();
                    app.editor_loaded_id = None; 
                }
            });
        });
    } else {
            ui.label("Waiting for traffic...");
    }
}
