use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum IntruderMode {
    Native,
    Browser,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum PayloadTransform {
    Identity,
    Base64,
    MD5,
}

#[derive(PartialEq)]
#[allow(dead_code)]
pub enum Tab {
    Dashboard,
    Intercept,
    History,
    Repeater,
    Scope,
    Intruder,
    Recon,
    PortScanner,
    ActiveScanner,
    Sniffer,
    Crawler,
    Decoder,

    Auth,
    Collaborator,
    WebSockets,
    Diff,
    Scripting,
    JWT,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScannerFinding {
    pub url: String,
    pub vuln_type: String, // "SQLi", "XSS", "Error"
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InterceptedRequest {
    pub id: u32,
    pub method: String,
    pub url: String,
    pub headers: serde_json::Value,
    pub body: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InterceptedResponse {
    pub id: u32,
    pub status: u16,
    pub headers: serde_json::Value,
    pub body: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum InterceptItem {
    Request(InterceptedRequest),
    Response(InterceptedResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItem {
    pub id: u32,
    pub method: String,
    pub url: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct IntruderResult {
    pub payload: String,
    pub status: u16,
    pub length: usize,
}

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AttackMode {
    Sniper,
    Pitchfork,
    ClusterBomb,
}

#[derive(Clone, Debug)]
pub struct AsyncIntruderJob {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body_template: String,
    pub payload_sets: Vec<Vec<String>>, // Support multiple sets
    pub attack_mode: AttackMode,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum AsyncIntruderResult {
    Progress { idx: usize, payload: String, status: u16, length: usize },
    Finished,
}

#[derive(Clone, Debug)]
pub struct AsyncReconJob {
    pub domain: String,
    pub wordlist: Vec<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum AsyncReconResult {
    Found { subdomain: String, ip: String },
    Finished,
}

#[derive(Clone, Debug)]
pub struct AsyncPortScanJob {
    pub target: String,
    pub ports: Vec<u16>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum AsyncPortScanResult {
    Open { port: u16, service: String },
    Finished,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AsyncActiveScanJob {
    pub url: String,
    pub param: String,
    pub original_value: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ActiveScanFinding {
    pub url: String,
    pub param: String,
    pub vuln_type: String,
    pub payload: String,
    pub evidence: String,
    pub severity: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum AsyncActiveScanResult {
    Finding(ActiveScanFinding),
    Progress { tested: usize },
    Finished,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OASTInteraction {
    pub id: String, // UUID
    pub timestamp: String,
    pub src_ip: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum WSMessage {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WSHistoryItem {
    pub timestamp: String,
    pub direction: String, // "Sent" or "Received"
    pub message: WSMessage,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(dead_code)]
pub struct VantaProject {
    pub history: Vec<HistoryItem>,
    pub scope_domains: Vec<String>,
    pub crawl_results: Vec<String>,
    pub crawl_vulnerabilities: Vec<String>,
    pub crawl_target: String,
    pub scanner_findings: Vec<ScannerFinding>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "command")]
pub enum NodeCommand {
    NAVIGATE {
        url: String,
    },
    CONTINUE {
        id: u32,
        method: String,
        headers: serde_json::Value,
        body: Option<String>,
        #[serde(rename = "interceptResponse")]
        intercept_response: bool,
    },
    #[serde(rename = "FULFILL_RESPONSE")]
    FulfillResponse {
        id: u32,
        status: u16,
        headers: serde_json::Value,
        body: String,
    },
    #[serde(rename = "SEND_REQUEST")]
    SendRequest {
        id: u32,
        method: String,
        url: String,
        headers: serde_json::Value,
        body: Option<String>,
    },
    DROP {
        id: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "event")]
pub enum NodeEvent {
    READY,
    #[serde(rename = "REQUEST_INTERCEPTED")]
    RequestIntercepted {
        id: u32,
        method: String,
        url: String,
        headers: serde_json::Value,
        body: Option<String>,
    },
    #[serde(rename = "RESPONSE_INTERCEPTED")]
    ResponseIntercepted {
        id: u32,
        status: u16,
        headers: serde_json::Value,
        body: String,
    },
    #[serde(rename = "REPEATER_RESPONSE")]
    RepeaterResponse {
        id: u32,
        status: u16,
        headers: serde_json::Value,
        body: String,
    },
    LOG {
        message: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthProfile {
    pub enabled: bool,
    pub trigger_status_codes: Vec<u16>, // e.g., [401, 403]
    pub trigger_body_match: String,     // e.g., "Session expired"
    
    // We store the "Login Request" parts directly to avoid circular dependency or complex nesting
    pub login_url: String,
    pub login_method: String,
    pub login_headers: Vec<(String, String)>,
    pub login_body: String,

    pub token_extraction_regex: String, // Regex to grab token from response
    pub token_dest_header: String,      // e.g., "Authorization"
    pub token_format: String,           // e.g., "Bearer {}"

    // Smart Setup Helpers
    pub target_username: String,
    pub target_password: String,
}

impl Default for AuthProfile {
    fn default() -> Self {
        Self {
            enabled: false,
            trigger_status_codes: vec![401],
            trigger_body_match: String::new(),
            login_url: String::new(),
            login_method: "POST".to_string(),
            login_headers: Vec::new(),
            login_body: String::new(),
            token_extraction_regex: String::new(),
            token_dest_header: "Authorization".to_string(),
            token_format: "Bearer {}".to_string(),
            target_username: String::new(),
            target_password: String::new(),
        }
    }
}
