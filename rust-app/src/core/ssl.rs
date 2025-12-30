use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SslInfo {
    pub subject: String,
    pub issuer: String,
    pub validity: String,
    pub raw_output: String,
}

pub fn check_ssl(target: &str) -> SslInfo {
    // 1. Prepare target format (host:port)
    let target_host = if target.contains("://") {
        target.split("://").nth(1).unwrap_or(target)
    } else {
        target
    };
    
    let target_addr = if target_host.contains(":") {
        target_host.to_string()
    } else {
        format!("{}:443", target_host)
    };

    // 2. Run OpenSSL s_client
    // echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -text
    
    // We run this as two separate commands or a shell command. 
    // Ideally avoids shell for security, but piping is hard with Command alone without extensive boilerplate.
    // Let's use `sh -c` for MVP simplicity and piping capability.
    
    let cmd_str = format!("echo | openssl s_client -connect {} 2>/dev/null | openssl x509 -noout -text", target_addr);
    
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd_str)
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        if stdout.is_empty() {
             return SslInfo { raw_output: "Failed to retrieve certificate. Is host reachable?".to_string(), ..Default::default() };
        }
        
        let subject = extract_field(&stdout, "Subject:");
        let issuer = extract_field(&stdout, "Issuer:");
        let validity = extract_validity(&stdout);

        return SslInfo {
            subject,
            issuer,
            validity,
            raw_output: stdout,
        };
    }

    SslInfo { raw_output: "Error executing OpenSSL command.".to_string(), ..Default::default() }
}

fn extract_field(haystack: &str, field: &str) -> String {
    for line in haystack.lines() {
        if let Some(idx) = line.find(field) {
            return line[idx + field.len()..].trim().to_string();
        }
    }
    "Unknown".to_string()
}

fn extract_validity(haystack: &str) -> String {
    let mut val = String::new();
    let mut capturing = false;
    for line in haystack.lines() {
        if line.trim().starts_with("Validity") {
            capturing = true;
            continue;
        }
        if capturing {
            if line.trim().starts_with("Not Before") || line.trim().starts_with("Not After") {
                 val.push_str(line.trim());
                 val.push_str("\n");
            } else {
                break; // End of validity block usually
            }
        }
    }
    if val.is_empty() { "Unknown".to_string() } else { val }
}
