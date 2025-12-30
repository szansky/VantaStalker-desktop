use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use directories::BaseDirs;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    pub user_agent: String,
    pub proxy_url: Option<String>,
    pub wordlists: HashMap<String, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            user_agent: "VantaStalker/2.1".to_string(),
            proxy_url: None,
            wordlists: HashMap::new(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let config_path = Self::get_config_path();
        
        if let Some(path) = &config_path {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(config) = toml::from_str(&content) {
                        return config;
                    } else {
                        eprintln!("Failed to parse config.toml");
                    }
                }
            } else {
                // Create default if not exists
                let default_config = Self::default();
                let _ = default_config.save();
                return default_config;
            }
        }
        
        Self::default()
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(path) = Self::get_config_path() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let content = toml::to_string_pretty(self).unwrap_or_default();
            fs::write(path, content)?;
        }
        Ok(())
    }

    fn get_config_path() -> Option<PathBuf> {
        if let Some(base_dirs) = BaseDirs::new() {
            // Use ~/.ventastalker/config.toml as requested
            let home = base_dirs.home_dir();
            return Some(home.join(".ventastalker").join("config.toml"));
        }
        None
    }
}
