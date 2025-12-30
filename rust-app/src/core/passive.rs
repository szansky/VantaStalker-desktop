use regex::Regex;
use crate::core::models::ActiveScanFinding;

#[allow(dead_code)]
pub struct PassiveRule {
    pub name: String,
    pub severity: String, // "High", "Medium", "Low", "Info"
    pub check: Box<dyn Fn(&str, &str, &str) -> Option<String> + Send + Sync>, // (url, headers_json, body) -> Option<Evidence>
}

pub fn scan_transaction(url: &str, headers: &str, body: &str) -> Vec<ActiveScanFinding> {
    let mut findings = Vec::new();

    // 1. Email Leak (PII)
    let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    if let Some(mat) = email_regex.find(body) {
        findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Body".to_string(),
            vuln_type: "PII Leak (Email)".to_string(),
            payload: "Passive".to_string(),
            evidence: mat.as_str().to_string(),
            severity: "Low".to_string(),
        });
    }

    // 2. AWS Access Key
    let aws_regex = Regex::new(r"(AKIA|ASIA)[0-9A-Z]{16}").unwrap();
    if let Some(mat) = aws_regex.find(body) {
        findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Body".to_string(),
            vuln_type: "Secret Leak (AWS Key)".to_string(),
            payload: "Passive".to_string(),
            evidence: mat.as_str().to_string(),
            severity: "High".to_string(),
        });
    }

    // 3. Generic API Key (Weak Heuristic: "api_key" = "...")
    let apikey_regex = Regex::new(r#"(?i)(api_key|apikey|secret|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]"#).unwrap();
    if let Some(caps) = apikey_regex.captures(body) {
        if let Some(val) = caps.get(2) {
             findings.push(ActiveScanFinding {
                url: url.to_string(),
                param: "Body".to_string(),
                vuln_type: "Potential API Key".to_string(),
                payload: "Passive".to_string(),
                evidence: val.as_str().to_string(),
                severity: "Medium".to_string(),
            });
        }
    }

    // 4. Security Headers (Check headers string)
    // Note: headers input is expected to be a string dump or JSON. 
    // For simplicity, we search the string.
    let headers_lower = headers.to_lowercase();
    
    if !headers_lower.contains("strict-transport-security") && url.starts_with("https") {
         findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Header".to_string(),
            vuln_type: "Missing HSTS".to_string(),
            payload: "Passive".to_string(),
            evidence: "Strict-Transport-Security header missing".to_string(),
            severity: "Low".to_string(),
        });
    }

    if !headers_lower.contains("x-frame-options") && !headers_lower.contains("content-security-policy") {
        findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Header".to_string(),
            vuln_type: "Clickjacking Risk".to_string(),
            payload: "Passive".to_string(),
            evidence: "X-Frame-Options and CSP missing".to_string(),
            severity: "Low".to_string(),
        });
    }
    
    if headers_lower.contains("server:") || headers_lower.contains("x-powered-by:") {
        // This is a bit too noisy, maybe only check for version numbers?
        // Let's rely on specific patterns if needed. 
        // For now, let's flag specific known bads if we want.
    }

    // 5. CORS Misconfigurations
    // We need to parse headers a bit more robustly for this if possible, but string search works for MVP
    // Heuristic: Check for "access-control-allow-origin: *" AND "access-control-allow-credentials: true"
    // Note: Browsers block this anyway, but it indicates misconfig.
    // A more dangerous one is reflection, but we can't detect reflection passively easily without seeing the REQUEST origin.
    // We can detecting "null" origin though.
    
    if headers_lower.contains("access-control-allow-origin: *") && headers_lower.contains("access-control-allow-credentials: true") {
         findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Header".to_string(),
            vuln_type: "CORS Misconfiguration".to_string(),
            payload: "Passive".to_string(),
            evidence: "ACAO: * and ACAC: true".to_string(),
            severity: "High".to_string(),
        });
    }

    if headers_lower.contains("access-control-allow-origin: null") {
         findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Header".to_string(),
            vuln_type: "CORS Misconfiguration".to_string(),
            payload: "Passive".to_string(),
            evidence: "ACAO: null".to_string(),
            severity: "High".to_string(),
        });
    }

    // 6. GraphQL Detection
    // URL Check
    if url.contains("/graphql") || url.contains("/v1/graphql") || url.contains("/api/graphql") {
         findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "URL".to_string(),
            vuln_type: "GraphQL Endpoint".to_string(),
            payload: "Passive".to_string(),
            evidence: "URL contains graphql".to_string(),
            severity: "Info".to_string(),
        });
    }

    // Body Check (Heuristic for GraphQL Errors)
    if body.contains("\"errors\"") && body.contains("\"message\"") && (body.contains("Cannot query field") || body.contains("Syntax Error")) {
          findings.push(ActiveScanFinding {
            url: url.to_string(),
            param: "Body".to_string(),
            vuln_type: "GraphQL Error".to_string(),
            payload: "Passive".to_string(),
            evidence: "Response body contains GraphQL error structure".to_string(),
            severity: "Low".to_string(),
        });
    }

    findings
}
