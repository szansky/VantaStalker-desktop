use similar::{ChangeTag, TextDiff};

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub content: String,
    pub tag: ChangeTag, // Equal, Delete, Insert
}

pub fn compute_diff(text_a: &str, text_b: &str) -> Vec<DiffLine> {
    let diff = TextDiff::from_lines(text_a, text_b);
    let mut lines = Vec::new();

    for change in diff.iter_all_changes() {
        lines.push(DiffLine {
            content: change.value().to_string(), // Keep whitespace? from_lines usually handles it.
            tag: change.tag(),
        });
    }

    lines
}
