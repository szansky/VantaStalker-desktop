use eframe::egui;
use crate::app::VantaApp;
use base64::prelude::*;

pub fn render(app: &mut VantaApp, ui: &mut egui::Ui) {
    ui.heading("🪄 Decoder / Encoder");
    
    ui.label("Input:");
    ui.text_edit_multiline(&mut app.decoder_input);
    
    ui.horizontal_wrapped(|ui| {
        if ui.button("Base64 Encode").clicked() {
            app.decoder_output = BASE64_STANDARD.encode(app.decoder_input.as_bytes());
        }
        if ui.button("Base64 Decode").clicked() {
             if let Ok(bytes) = BASE64_STANDARD.decode(app.decoder_input.trim()) {
                app.decoder_output = String::from_utf8_lossy(&bytes).to_string();
            } else {
                app.decoder_output = "Error: Invalid Base64".into();
            }
        }
        if ui.button("URL Encode").clicked() {
            app.decoder_output = urlencoding::encode(&app.decoder_input).to_string();
        }
        if ui.button("URL Decode").clicked() {
            if let Ok(s) = urlencoding::decode(&app.decoder_input) {
                app.decoder_output = s.to_string();
            }
        }
        // Hex Removed due to missing crate
        
         if ui.button("JWT Decode").clicked() {
            // Split by .
            let parts: Vec<&str> = app.decoder_input.split('.').collect();
            if parts.len() == 3 {
                 let header = parts[0];
                 let payload = parts[1];
                 let signature = parts[2];
                 
                 let decode_part = |p: &str| -> String {
                     // JWT uses URL-safe base64, usually no padding, but we might need to add it or use proper decoder
                     // Let's try engine URL_SAFE_NO_PAD
                     if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p) {
                         String::from_utf8_lossy(&bytes).to_string()
                     } else {
                         // Fallback to standard? Or add padding
                         "Invalid Base64".into()
                     }
                 };
                 
                 let h_json = decode_part(header);
                 let p_json = decode_part(payload);
                 
                 // Pretty print if json
                let h_pretty = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&h_json) { serde_json::to_string_pretty(&v).unwrap() } else { h_json };
                let p_pretty = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&p_json) { serde_json::to_string_pretty(&v).unwrap() } else { p_json };

                 app.decoder_output = format!("Header:\n{}\n\nPayload:\n{}\n\nSignature:\n{}", h_pretty, p_pretty, signature);
            } else {
                app.decoder_output = "Error: Invalid JWT format (expected 3 parts)".into();
            }
        }
    });
    
    ui.label("Output:");
    ui.text_edit_multiline(&mut app.decoder_output);
}
