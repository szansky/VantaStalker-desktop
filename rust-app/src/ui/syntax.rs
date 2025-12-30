use eframe::egui;
use regex::Regex;
use std::sync::OnceLock;

static JSON_REGEX: OnceLock<Regex> = OnceLock::new();
static HTML_REGEX: OnceLock<Regex> = OnceLock::new();

pub fn highlight(ui: &egui::Ui, text: &str, language: &str) -> egui::text::LayoutJob {
    let theme = if ui.visuals().dark_mode {
        Theme::dark()
    } else {
        Theme::light()
    };

    match language {
        "json" => highlight_json(text, &theme),
        "html" => highlight_html(text, &theme),
        _ => {
            let mut job = egui::text::LayoutJob::default();
            job.append(text, 0.0, egui::TextFormat {
                font_id: egui::FontId::monospace(14.0),
                color: theme.text,
                ..Default::default()
            });
            job
        }
    }
}

struct Theme {
    text: egui::Color32,
    keyword: egui::Color32,
    string: egui::Color32,
    number: egui::Color32,
    comment: egui::Color32,
}

impl Theme {
    fn dark() -> Self {
        Self {
            text: egui::Color32::from_gray(230),
            keyword: egui::Color32::from_rgb(255, 120, 120), // Reddish for keys
            string: egui::Color32::from_rgb(150, 230, 150), // Greenish
            number: egui::Color32::from_rgb(120, 180, 255), // Blueish
            comment: egui::Color32::from_gray(120),
        }
    }
    
    fn light() -> Self {
        Self {
            text: egui::Color32::BLACK,
            keyword: egui::Color32::from_rgb(180, 0, 0),
            string: egui::Color32::from_rgb(0, 120, 0),
            number: egui::Color32::from_rgb(0, 0, 180),
            comment: egui::Color32::from_gray(120),
        }
    }
}

fn highlight_json(text: &str, theme: &Theme) -> egui::text::LayoutJob {
    let regex = JSON_REGEX.get_or_init(|| {
        Regex::new(r#"(?P<key>"[^"]*"\s*:)|(?P<string>"[^"]*")|(?P<number>\b\d+(\.\d*)?\b)|(?P<bool>true|false|null)"#).unwrap()
    });

    let mut job = egui::text::LayoutJob::default();
    let mut last_end = 0;

    for caps in regex.captures_iter(text) {
        if let Some(m) = caps.get(0) {
            // Append plaintext before match
            if m.start() > last_end {
                job.append(&text[last_end..m.start()], 0.0, format(theme.text));
            }

            // Determine color
            let color = if caps.name("key").is_some() {
                theme.keyword
            } else if caps.name("string").is_some() {
                theme.string
            } else if caps.name("number").is_some() {
                theme.number
            } else if caps.name("bool").is_some() {
                theme.number
            } else {
                theme.text
            };

            job.append(m.as_str(), 0.0, format(color));
            last_end = m.end();
        }
    }

    // Append remaining
    if last_end < text.len() {
        job.append(&text[last_end..], 0.0, format(theme.text));
    }

    job
}

fn highlight_html(text: &str, theme: &Theme) -> egui::text::LayoutJob {
     let regex = HTML_REGEX.get_or_init(|| {
        Regex::new(r#"(?P<tag></?[\w\-]+)|(?P<attr>\s[\w\-]+=)|(?P<string>"[^"]*")|(?P<comment><!--.*?-->)"#).unwrap()
    });

    let mut job = egui::text::LayoutJob::default();
    let mut last_end = 0;

    for caps in regex.captures_iter(text) {
         if let Some(m) = caps.get(0) {
            // Append plaintext before match
            if m.start() > last_end {
                job.append(&text[last_end..m.start()], 0.0, format(theme.text));
            }

            let color = if caps.name("tag").is_some() {
                theme.keyword
            } else if caps.name("attr").is_some() {
                theme.number // reuse number color for attributes
            } else if caps.name("string").is_some() {
                theme.string
            } else if caps.name("comment").is_some() {
                theme.comment
            } else {
                theme.text
            };

            job.append(m.as_str(), 0.0, format(color));
            last_end = m.end();
        }
    }

    if last_end < text.len() {
        job.append(&text[last_end..], 0.0, format(theme.text));
    }
    job
}

fn format(color: egui::Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: egui::FontId::monospace(14.0),
        color,
        ..Default::default()
    }
}
