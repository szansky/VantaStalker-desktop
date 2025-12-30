use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteMapNode {
    pub name: String,
    pub is_file: bool,
    pub children: BTreeMap<String, SiteMapNode>,
    pub full_url: Option<String>,
}

impl Default for SiteMapNode {
    fn default() -> Self {
        Self {
            name: "root".to_string(),
            is_file: false,
            children: BTreeMap::new(),
            full_url: None,
        }
    }
}

pub fn insert_url(root: &mut SiteMapNode, url_str: &str) {
    if let Ok(url) = Url::parse(url_str) {
        // 1. Domain
        let domain = url.host_str().unwrap_or("unknown").to_string();
        let domain_node = root.children.entry(domain.clone()).or_insert_with(|| SiteMapNode {
            name: domain.clone(),
            is_file: false,
            children: BTreeMap::new(),
            full_url: Some(format!("{}://{}", url.scheme(), domain)),
        });

        // 2. Path Segments
        let path = url.path();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        let mut current_node = domain_node;

        for (i, segment) in segments.iter().enumerate() {
            let is_last = i == segments.len() - 1;
            // Simple heuristic for file: check extension or if logic dictates. 
            // For now, assume last segment is file if it has a dot, else folder? 
            // Better: just treat everything as nodes.
            // But let's check for '.' for visual indication.
            let is_file = is_last && segment.contains('.');

            current_node = current_node.children.entry(segment.to_string()).or_insert_with(|| SiteMapNode {
                name: segment.to_string(),
                is_file,
                children: BTreeMap::new(),
                // Reconstruct URL (approximate) could be complex, for now we map full URL only to leaf or specific nodes if needed.
                // We'll leave full_url None for intermediate folders unless we track it properly.
                full_url: None, 
            });
            
            // If it's the last segment (leaf), we might want to store the full original URL (including query params?)
            if is_last {
                 current_node.full_url = Some(url_str.to_string());
            }
        }
    }
}
