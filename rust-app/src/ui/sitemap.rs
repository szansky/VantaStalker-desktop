use eframe::egui::{self, CollapsingHeader};
use crate::core::sitemap::SiteMapNode;

pub fn render_tree(ui: &mut egui::Ui, node: &SiteMapNode) {
    for (name, child) in &node.children {
        if child.children.is_empty() {
             // Leaf (File or empty folder)
             ui.horizontal(|ui| {
                 ui.label(if child.is_file { "📄" } else { "📁" });
                 // Make selectable or clickable to view details?
                 if ui.button(name).clicked() {
                     // Potential action: Load into Scope or Repeater
                     // For now just console log or logic hook
                     if let Some(url) = &child.full_url {
                         // Copy to clipboard or set as target?
                         ui.output_mut(|o| o.copied_text = url.clone());
                     }
                 }
             });
        } else {
            // Node with children (Folder)
             CollapsingHeader::new(format!("📁 {}", name))
                .default_open(false)
                .show(ui, |ui| {
                    render_tree(ui, child);
                });
        }
    }
}

pub fn render_panel(app: &mut crate::app::VantaApp, ui: &mut egui::Ui) {
    ui.heading("🗺️ Site Map");
    ui.separator();
    
    egui::ScrollArea::vertical().show(ui, |ui| {
        render_tree(ui, &app.sitemap_root);
    });
}
