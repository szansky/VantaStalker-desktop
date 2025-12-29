use eframe::egui::{self, Visuals, Color32};
use egui_extras::{TableBuilder, Column};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque, HashMap};
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::mpsc as tokio_mpsc;
use std::thread;
use url::Url;
use base64::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use scraper::{Html, Selector};
use rayon::prelude::*;
use std::net::IpAddr;
use rfd::FileDialog;
use md5::Md5;
use rusqlite::{params, Connection};
use hickory_resolver::Resolver as HickoryResolver;

#[derive(PartialEq, Debug, Clone, Copy)]
enum IntruderMode {
    Native,
    Browser,
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum PayloadTransform {
    Identity,
    Base64,
    MD5,
}

#[derive(PartialEq)]
enum Tab {
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScannerFinding {
    url: String,
    vuln_type: String, // "SQLi", "XSS", "Error"
    payload: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct InterceptedRequest {
    id: u32,
    method: String,
    url: String,
    headers: serde_json::Value,
    body: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct InterceptedResponse {
    id: u32,
    status: u16,
    headers: serde_json::Value,
    body: String,
}

#[derive(Debug, Clone)]
enum InterceptItem {
    Request(InterceptedRequest),
    Response(InterceptedResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryItem {
    id: u32,
    method: String,
    url: String,
    status: String,
}

#[derive(Debug, Clone)]
struct IntruderResult {
    payload: String,
    status: u16,
    length: usize,
}

#[derive(Clone, Debug)]
struct AsyncIntruderJob {
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body_template: String,
    payloads: Vec<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum AsyncIntruderResult {
    Progress { idx: usize, payload: String, status: u16, length: usize },
    Finished,
}

#[derive(Clone, Debug)]
struct AsyncReconJob {
    domain: String,
    wordlist: Vec<String>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum AsyncReconResult {
    Found { subdomain: String, ip: String },
    Finished,
}

#[derive(Clone, Debug)]
struct AsyncPortScanJob {
    target: String,
    ports: Vec<u16>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum AsyncPortScanResult {
    Open { port: u16, service: String },
    Finished,
}

#[derive(Clone, Debug)]
struct AsyncActiveScanJob {
    url: String,
    param: String,
    original_value: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ActiveScanFinding {
    url: String,
    param: String,
    vuln_type: String,
    payload: String,
    evidence: String,
    severity: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum AsyncActiveScanResult {
    Finding(ActiveScanFinding),
    Progress { tested: usize },
    Finished,
}

#[derive(Clone, Debug)]
struct CapturedPacket {
    timestamp: String,
    src_ip: String,
    dst_ip: String,
    protocol: String,
    length: usize,
    info: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VantaProject {
    history: Vec<HistoryItem>,
    scope_domains: Vec<String>,
    crawl_results: Vec<String>,
    crawl_vulnerabilities: Vec<String>,
    crawl_target: String,
    scanner_findings: Vec<ScannerFinding>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "command")]
enum NodeCommand {
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
enum NodeEvent {
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

struct VantaApp {
    // UI State
    target_url: String,
    logs: Vec<String>,
    intercept_enabled: bool,
    intercept_responses: bool, 
    active_tab: Tab,
    
    // Data State
    queue: VecDeque<InterceptItem>, 
    history: Vec<HistoryItem>,
    
    // Scope State
    scope_domains: Vec<String>,
    new_scope_domain: String,

    // Intercept Editor
    edit_method: String,
    edit_url: String, 
    edit_status: String, 
    edit_body: String,
    edit_headers: Vec<(String, String)>,

    // Repeater State
    rep_url: String,
    rep_method: String,
    rep_headers: Vec<(String, String)>,
    rep_body: String,
    rep_response: String,

    // Intruder State
    intr_url: String,
    intr_method: String,
    intr_headers: Vec<(String, String)>,
    intr_body_template: String, 
    intr_payloads: String, 
    intr_results: Vec<IntruderResult>,
    intr_running: bool,
    intr_current_idx: usize,
    intr_mode: IntruderMode,
    intr_transform: PayloadTransform,
    
    // Crawler State
    crawl_discovered: HashSet<String>,
    crawl_results: Vec<String>,
    crawl_vulnerabilities: Vec<String>, // "Report" items
    crawl_active: bool,
    crawl_target: String,
    crawl_current_url: String, // "Now scanning..."
    crawl_queue: VecDeque<String>,
    _crawl_max_depth: u32,
    _crawl_current_depth: u32,
    crawl_timer: f32,
    crawl_idle_timer: f32, // Auto-stop detection
    show_report: bool, // Modal state

    // Active Scanner State
    scanner_active: bool,
    scanner_queue: VecDeque<String>, // URLs with params to probe
    scanner_findings: Vec<ScannerFinding>,

    pending_scans: HashMap<u32, (String, String)>, // ID -> (Url, Payload)
    scan_id_counter: u32,

    // IPC Channels
    tx_command: Sender<NodeCommand>,
    rx_event: Receiver<NodeEvent>,

    // Recon State
    recon_domain: String,
    recon_wordlist: String,
    recon_results: Vec<(String, String)>,
    recon_running: bool,

    // Async Intruder Channel
    tx_intruder_job: tokio_mpsc::UnboundedSender<AsyncIntruderJob>,
    rx_intruder_result: Receiver<AsyncIntruderResult>,
    
    // Async Recon Channel
    tx_recon_job: tokio_mpsc::UnboundedSender<AsyncReconJob>,
    rx_recon_result: Receiver<AsyncReconResult>,

    // Port Scanner State
    portscan_target: String,
    portscan_port_range: String,
    portscan_results: Vec<(u16, String)>,
    portscan_running: bool,
    
    // Async Port Scanner Channel
    tx_portscan_job: tokio_mpsc::UnboundedSender<AsyncPortScanJob>,
    rx_portscan_result: Receiver<AsyncPortScanResult>,

    // Active Scanner State
    activescan_target_url: String,
    activescan_findings: Vec<ActiveScanFinding>,
    activescan_running: bool,
    activescan_tested: usize,
    
    // Async Active Scanner Channel
    tx_activescan_job: tokio_mpsc::UnboundedSender<AsyncActiveScanJob>,
    rx_activescan_result: Receiver<AsyncActiveScanResult>,

    // Sniffer State
    sniffer_packets: Vec<CapturedPacket>,
    sniffer_running: bool,
    sniffer_interface: String,
    rx_sniffer: Receiver<CapturedPacket>,
    sniffer_stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,

    editor_loaded_id: Option<u32>, 
    editor_is_response: bool,

    // Decoder State
    decoder_input: String,
    decoder_output: String,
    // Layout / Theme
    is_dark_mode: bool,
    conn: Connection,
}

impl VantaApp {
    fn new(_cc: &eframe::CreationContext) -> Self {
        let (tx_command, rx_cmd_thread) = mpsc::channel::<NodeCommand>();
        let (tx_event, rx_event) = mpsc::channel::<NodeEvent>();
        
        // Native Async Intruder Channels (Tokio)
        let (tx_intruder_job, mut rx_job_thread) = tokio_mpsc::unbounded_channel::<AsyncIntruderJob>();
        let (tx_intruder_res, rx_intruder_result) = mpsc::channel::<AsyncIntruderResult>();
        let tx_intruder_res_clone = tx_intruder_res.clone();

        // Native Async Recon Channels (Tokio)
        let (tx_recon_job, mut rx_recon_thread) = tokio_mpsc::unbounded_channel::<AsyncReconJob>();
        let (tx_recon_res, rx_recon_result) = mpsc::channel::<AsyncReconResult>();
        let tx_recon_res_clone = tx_recon_res.clone();

        // Native Async Port Scanner Channels (Tokio)
        let (tx_portscan_job, mut rx_portscan_thread) = tokio_mpsc::unbounded_channel::<AsyncPortScanJob>();
        let (tx_portscan_res, rx_portscan_result) = mpsc::channel::<AsyncPortScanResult>();
        let tx_portscan_res_clone = tx_portscan_res.clone();

        // Native Async Active Scanner Channels (Tokio)
        let (tx_activescan_job, mut rx_activescan_thread) = tokio_mpsc::unbounded_channel::<AsyncActiveScanJob>();
        let (tx_activescan_res, rx_activescan_result) = mpsc::channel::<AsyncActiveScanResult>();
        let tx_activescan_res_clone = tx_activescan_res.clone();

        // Spawn Tokio Runtime Thread
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async move {
                // We use select! to handle both job queues concurrently
                loop {
                    tokio::select! {
                        Some(job) = rx_job_thread.recv() => {
                             let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .redirect(reqwest::redirect::Policy::none())
                                .build()
                                .unwrap();
        
                             let payloads = job.payloads;
                             let template = Arc::new(job.body_template);
                             let url = Arc::new(job.url);
                             let method = Arc::new(job.method);
                             let headers = Arc::new(job.headers);
                             
                             let tx = tx_intruder_res_clone.clone();

                             // Spawn concurrent requests for this job
                             for (idx, payload) in payloads.into_iter().enumerate() {
                                 let p = payload.clone();
                                 let client = client.clone();
                                 let tx = tx.clone();
                                 let tmpl = template.clone();
                                 let u = url.clone();
                                 let m = method.clone();
                                 let h = headers.clone();
                                 
                                 tokio::spawn(async move {
                                     let body = tmpl.replace("§payload§", &p);
                                     let mut req_builder = match m.as_str() {
                                         "POST" => client.post(u.as_str()),
                                         "PUT" => client.put(u.as_str()),
                                         "DELETE" => client.delete(u.as_str()),
                                         _ => client.get(u.as_str()),
                                     };
                                     for (k, v) in h.iter() { req_builder = req_builder.header(k, v); }
                                     if !body.is_empty() { req_builder = req_builder.body(body); }
        
                                     match req_builder.send().await {
                                         Ok(resp) => {
                                             let status = resp.status().as_u16();
                                             let len = resp.content_length().unwrap_or(0) as usize; 
                                             let _ = tx.send(AsyncIntruderResult::Progress { idx, payload: p, status, length: len });
                                         },
                                         Err(_) => {
                                              let _ = tx.send(AsyncIntruderResult::Progress { idx, payload: p, status: 0, length: 0 });
                                         }
                                     }
                                 });
                             }
                        },
                        Some(job) = rx_recon_thread.recv() => {
                            // hickory-resolver 0.25 uses builder pattern
                            let resolver = match HickoryResolver::builder_tokio() {
                                Ok(builder) => builder.build(),
                                Err(_) => continue,
                            };
                            
                            let tx = tx_recon_res_clone.clone();
                            let domain = job.domain;
                            
                            for sub in job.wordlist {
                                let target = format!("{}.{}", sub, domain);
                                let resolver = resolver.clone();
                                let tx = tx.clone();
                                
                                tokio::spawn(async move {
                                    if let Ok(response) = resolver.lookup_ip(&target).await {
                                        let ips: Vec<IpAddr> = response.iter().collect();
                                        if let Some(ip) = ips.first() {
                                            let ip_str: String = ip.to_string();
                                            let _ = tx.send(AsyncReconResult::Found { 
                                                subdomain: target, 
                                                ip: ip_str 
                                            });
                                        }
                                    }
                                });
                            }
                        },
                        Some(job) = rx_portscan_thread.recv() => {
                            let tx = tx_portscan_res_clone.clone();
                            let target = job.target;
                            
                            for port in job.ports {
                                let target = target.clone();
                                let tx = tx.clone();
                                
                                tokio::spawn(async move {
                                    use tokio::net::TcpStream;
                                    use tokio::time::{timeout, Duration};
                                    
                                    let addr = format!("{}:{}", target, port);
                                    
                                    // Try to connect with 1s timeout
                                    if let Ok(Ok(_)) = timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await {
                                        // Port is open - identify common services
                                        let service = match port {
                                            21 => "FTP".to_string(),
                                            22 => "SSH".to_string(),
                                            23 => "Telnet".to_string(),
                                            25 => "SMTP".to_string(),
                                            53 => "DNS".to_string(),
                                            80 => "HTTP".to_string(),
                                            110 => "POP3".to_string(),
                                            143 => "IMAP".to_string(),
                                            443 => "HTTPS".to_string(),
                                            445 => "SMB".to_string(),
                                            3306 => "MySQL".to_string(),
                                            3389 => "RDP".to_string(),
                                            5432 => "PostgreSQL".to_string(),
                                            5900 => "VNC".to_string(),
                                            6379 => "Redis".to_string(),
                                            8080 => "HTTP-Proxy".to_string(),
                                            8443 => "HTTPS-Alt".to_string(),
                                            27017 => "MongoDB".to_string(),
                                            _ => "Unknown".to_string(),
                                        };
                                        let _ = tx.send(AsyncPortScanResult::Open { port, service });
                                    }
                                });
                            }
                        },
                        Some(job) = rx_activescan_thread.recv() => {
                            let tx = tx_activescan_res_clone.clone();
                            let url_base = job.url;
                            let param = job.param;
                            let _original = job.original_value;
                            
                            // Vulnerability payloads
                            let sqli_payloads = vec![
                                ("' OR '1'='1", "SQL Injection"),
                                ("' OR 1=1--", "SQL Injection"),
                                ("1' AND '1'='1", "SQL Injection"),
                                ("'; DROP TABLE users;--", "SQL Injection"),
                                ("1 UNION SELECT NULL--", "SQL Injection"),
                            ];
                            
                            let xss_payloads = vec![
                                ("<script>alert(1)</script>", "XSS"),
                                ("<img src=x onerror=alert(1)>", "XSS"),
                                ("javascript:alert(1)", "XSS"),
                                ("<svg onload=alert(1)>", "XSS"),
                            ];
                            
                            let cmdi_payloads = vec![
                                ("; ls", "Command Injection"),
                                ("| cat /etc/passwd", "Command Injection"),
                                ("`id`", "Command Injection"),
                                ("$(whoami)", "Command Injection"),
                            ];
                            
                            let ssrf_payloads = vec![
                                ("http://127.0.0.1", "SSRF"),
                                ("http://localhost", "SSRF"),
                                ("http://169.254.169.254", "SSRF (AWS Metadata)"),
                            ];
                            
                            // Combine all payloads
                            let mut all_payloads: Vec<(&str, &str)> = Vec::new();
                            all_payloads.extend(sqli_payloads);
                            all_payloads.extend(xss_payloads);
                            all_payloads.extend(cmdi_payloads);
                            all_payloads.extend(ssrf_payloads);
                            
                            let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .timeout(std::time::Duration::from_secs(5))
                                .build()
                                .unwrap();
                            
                            for (payload, vuln_type) in all_payloads {
                                let tx = tx.clone();
                                let client = client.clone();
                                let url_base = url_base.clone();
                                let param = param.clone();
                                let payload = payload.to_string();
                                let vuln_type = vuln_type.to_string();
                                
                                tokio::spawn(async move {
                                    // Build URL with injected payload
                                    let test_url = if url_base.contains('?') {
                                        format!("{}&{}={}", url_base, param, urlencoding::encode(&payload))
                                    } else {
                                        format!("{}?{}={}", url_base, param, urlencoding::encode(&payload))
                                    };
                                    
                                    if let Ok(resp) = client.get(&test_url).send().await {
                                        if let Ok(body) = resp.text().await {
                                            // Check for vulnerability indicators
                                            let is_vulnerable = match vuln_type.as_str() {
                                                "SQL Injection" => {
                                                    body.to_lowercase().contains("sql") ||
                                                    body.to_lowercase().contains("mysql") ||
                                                    body.to_lowercase().contains("syntax error") ||
                                                    body.to_lowercase().contains("query") ||
                                                    body.to_lowercase().contains("odbc") ||
                                                    body.to_lowercase().contains("postgresql")
                                                },
                                                "XSS" => {
                                                    body.contains(&payload)
                                                },
                                                "Command Injection" => {
                                                    body.contains("root:") ||
                                                    body.contains("uid=") ||
                                                    body.contains("/bin/")
                                                },
                                                _ if vuln_type.starts_with("SSRF") => {
                                                    body.contains("ami-") ||
                                                    body.contains("instance-id") ||
                                                    body.len() > 0 && !body.contains("error")
                                                },
                                                _ => false
                                            };
                                            
                                            if is_vulnerable {
                                                let finding = ActiveScanFinding {
                                                    url: test_url,
                                                    param: param.clone(),
                                                    vuln_type: vuln_type.clone(),
                                                    payload: payload.clone(),
                                                    evidence: body.chars().take(200).collect(),
                                                    severity: match vuln_type.as_str() {
                                                        "SQL Injection" => "HIGH".to_string(),
                                                        "Command Injection" => "CRITICAL".to_string(),
                                                        _ if vuln_type.starts_with("SSRF") => "HIGH".to_string(),
                                                        "XSS" => "MEDIUM".to_string(),
                                                        _ => "LOW".to_string(),
                                                    },
                                                };
                                                let _ = tx.send(AsyncActiveScanResult::Finding(finding));
                                            }
                                        }
                                    }
                                });
                            }
                        }
                        else => {
                            // All channels closed - app is shutting down
                            break;
                        }
                    }
                }
            });
        });

        thread::spawn(move || {
            let mut child = Command::new("npx")
                .arg("ts-node")
                .arg("../src/index.ts")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to start Node.js process");

            let mut stdin = child.stdin.take().expect("Failed to get stdin");
            let stdout = child.stdout.take().expect("Failed to get stdout");

            let tx_event_clone = tx_event.clone();
            thread::spawn(move || {
                let reader = io::BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        if l.trim().is_empty() { continue; }
                        if let Ok(event) = serde_json::from_str::<NodeEvent>(&l) {
                            tx_event_clone.send(event).ok();
                        } else {
                            tx_event_clone.send(NodeEvent::LOG { message: l }).ok();
                        }
                    }
                }
            });

            for cmd in rx_cmd_thread {
                if let Ok(json) = serde_json::to_string(&cmd) {
                    if stdin.write_all(json.as_bytes()).is_err() || stdin.write_all(b"\n").is_err() {
                        break; 
                    }
                }
            }
        });

        // Custom Cyberpunk/Dark Theme
        let mut visuals = Visuals::dark();
        visuals.window_rounding = egui::Rounding::same(8.0);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(20, 20, 25); 
        visuals.widgets.noninteractive.fg_stroke.color = Color32::from_rgb(220, 220, 220); // Brighter text
        
        // Buttons / Interactive
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(40, 40, 50);
        visuals.widgets.inactive.rounding = egui::Rounding::same(4.0);
        
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(60, 60, 75);
        visuals.widgets.hovered.fg_stroke.color = Color32::from_rgb(255, 255, 255);
        
        visuals.widgets.active.bg_fill = Color32::from_rgb(80, 80, 100);
        visuals.selection.bg_fill = Color32::from_rgb(0, 120, 215); // Neon Blue Selection
        
        _cc.egui_ctx.set_visuals(visuals);

        // Fonts could be customized here too, but default monospace is okay for hacker tool.
        
        // Init Database
        let conn = Connection::open("ventastalker.db").expect("Failed to open DB");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY,
                method TEXT,
                url TEXT,
                status TEXT,
                length INTEGER,
                p_type TEXT
            )",
            [],
        ).expect("Failed to create history table");

        Self {
            target_url: "http://example.com".to_owned(),
            logs: vec!["Refreshed GUI. Ready to launch.".to_owned()],
            intercept_enabled: true,
            intercept_responses: false,
            active_tab: Tab::Dashboard,
            queue: VecDeque::new(),
            history: Vec::new(),
            scope_domains: Vec::new(), // Initialized empty
            conn,                      // Move connection

            new_scope_domain: String::new(),
            edit_method: String::new(),
            edit_url: String::new(),
            edit_status: String::new(),
            edit_body: String::new(),
            edit_headers: Vec::new(),
            rep_url: "http://example.com".into(),
            rep_method: "GET".into(),
            rep_headers: vec![("User-Agent".into(), "VantaStalker/1.0".into())],
            rep_body: "".into(),
            rep_response: "No response yet.".into(),

            // Intruder Init
            intr_url: "http://example.com/login".into(),
            intr_method: "POST".into(),
            intr_headers: vec![("Content-Type".into(), "application/json".into())],
            intr_body_template: "{\"username\": \"admin\", \"password\": \"§payload§\"}".into(),
            intr_payloads: "123456\npassword\nadmin123\nqwerty".into(),
            intr_results: Vec::new(),
            intr_running: false,
            intr_current_idx: 0,
            intr_mode: IntruderMode::Native,
            intr_transform: PayloadTransform::Identity,
            
            // Crawler Init
            crawl_discovered: HashSet::new(),
            crawl_results: Vec::new(),
            crawl_vulnerabilities: Vec::new(),
            crawl_active: false,
            crawl_target: "http://example.com".into(),
            crawl_current_url: "Idle".into(),
            crawl_queue: VecDeque::new(),
            _crawl_max_depth: 2,
            _crawl_current_depth: 0,
            crawl_timer: 0.0,
            crawl_idle_timer: 0.0,
            // crawl_regex removed
            show_report: false,

            // Scanner Init
            scanner_active: false,
            scanner_queue: VecDeque::new(),
            scanner_findings: Vec::new(),
            pending_scans: HashMap::new(),
            scan_id_counter: 80000, 

            tx_command,
            rx_event,
            
            tx_intruder_job,
            rx_intruder_result,

            tx_recon_job,
            rx_recon_result,

            // Recon Init
            recon_domain: "example.com".into(),
            recon_wordlist: "www\nmail\ndev\nadmin\ntest".into(),
            recon_results: Vec::new(),
            recon_running: false,

            // Port Scanner Init
            portscan_target: "127.0.0.1".into(),
            portscan_port_range: "1-1000".into(),
            portscan_results: Vec::new(),
            portscan_running: false,
            
            tx_portscan_job,
            rx_portscan_result,

            // Active Scanner Init
            activescan_target_url: "http://example.com/search?q=test".into(),
            activescan_findings: Vec::new(),
            activescan_running: false,
            activescan_tested: 0,
            
            tx_activescan_job,
            rx_activescan_result,

            // Sniffer Init
            sniffer_packets: Vec::new(),
            sniffer_running: false,
            sniffer_interface: "eth0".into(),
            rx_sniffer: {
                let (_, rx) = mpsc::channel::<CapturedPacket>();
                rx
            },
            sniffer_stop_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),

            editor_loaded_id: None,
            editor_is_response: false,
            
            decoder_input: String::new(),
            decoder_output: String::new(),
            is_dark_mode: true,
        }
    }

    fn apply_theme(ctx: &egui::Context, dark: bool) {
        if dark {
            let mut visuals = Visuals::dark();
            visuals.window_rounding = egui::Rounding::same(8.0);
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(20, 20, 25); 
            visuals.widgets.noninteractive.fg_stroke.color = Color32::from_rgb(220, 220, 220); 
            
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(40, 40, 50);
            visuals.widgets.inactive.rounding = egui::Rounding::same(4.0);
            
            visuals.widgets.hovered.bg_fill = Color32::from_rgb(60, 60, 75);
            visuals.widgets.hovered.fg_stroke.color = Color32::from_rgb(255, 255, 255);
            
            visuals.widgets.active.bg_fill = Color32::from_rgb(80, 80, 100);
            visuals.selection.bg_fill = Color32::from_rgb(0, 120, 215);
            ctx.set_visuals(visuals);
        } else {
            let mut visuals = Visuals::light();
            visuals.window_rounding = egui::Rounding::same(8.0);
            // Light Pro Theme
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(240, 240, 245);
            visuals.widgets.noninteractive.fg_stroke.color = Color32::from_rgb(20, 20, 20);

            visuals.selection.bg_fill = Color32::from_rgb(0, 100, 200);
            ctx.set_visuals(visuals);
        }
    }

    fn sync_editor(&mut self) {
        if let Some(item) = self.queue.front() {
             let (id, is_resp) = match item {
                 InterceptItem::Request(r) => (r.id, false),
                 InterceptItem::Response(r) => (r.id, true),
             };

            if self.editor_loaded_id != Some(id) || self.editor_is_response != is_resp {
                self.edit_headers.clear();
                
                match item {
                    InterceptItem::Request(req) => {
                        self.edit_method = req.method.clone();
                        self.edit_url = req.url.clone();
                        self.edit_body = req.body.clone().unwrap_or_default();
                        if let Some(obj) = req.headers.as_object() {
                            for (k, v) in obj {
                                self.edit_headers.push((k.clone(), v.as_str().unwrap_or("").to_string()));
                            }
                        }
                    },
                    InterceptItem::Response(res) => {
                        self.edit_status = res.status.to_string();
                        self.edit_body = res.body.clone();
                        self.edit_url = format!("Response #{}", res.id); 
                        if let Some(obj) = res.headers.as_object() {
                             for (k, v) in obj {
                                self.edit_headers.push((k.clone(), v.as_str().unwrap_or("").to_string()));
                            }
                        }
                    }
                }
                
                self.editor_loaded_id = Some(id);
                self.editor_is_response = is_resp;
            }
        } else {
            self.editor_loaded_id = None;
        }
    }

    fn is_in_scope(&self, url: &str) -> bool {
        if self.scope_domains.is_empty() {
             return true; 
        }
        for domain in &self.scope_domains {
            if url.contains(domain) {
                return true;
            }
        }
        false
    }
    
    fn scan_content(&mut self, content: &str) {
        // Parse base URL (default to target if current is idle/invalid)
        let base_url = Url::parse(&self.crawl_current_url)
            .or_else(|_| Url::parse(&self.crawl_target))
            .unwrap_or_else(|_| Url::parse("http://localhost").unwrap());

        // Robust Parsing using Scraper
        let document = Html::parse_document(content);
        let link_selector = Selector::parse("a").unwrap();
        // let form_selector = Selector::parse("form").unwrap(); // Reserved for Scanner Phase

        // 1. Extract Links
        for element in document.select(&link_selector) {
            if let Some(href_val) = element.value().attr("href") {
                // Skip non-http schemes
                if href_val.starts_with("javascript:") || href_val.starts_with("mailto:") || href_val.starts_with("#") {
                    continue;
                }

                if let Ok(new_url) = base_url.join(href_val) {
                    let new_url_str = new_url.to_string();
                    
                    // EXTENSION FILTER
                    let path = new_url.path().to_lowercase();
                    if path.ends_with(".css") || 
                       path.ends_with(".js") || 
                       path.ends_with(".png") || 
                       path.ends_with(".jpg") || 
                       path.ends_with(".jpeg") || 
                       path.ends_with(".gif") || 
                       path.ends_with(".svg") || 
                       path.ends_with(".ico") || 
                       path.ends_with(".woff") || 
                       path.ends_with(".woff2") || 
                       path.ends_with(".ttf") || 
                       path.ends_with(".pdf") || 
                       path.ends_with(".zip") ||
                       path.ends_with(".xml") ||
                       path.ends_with(".json") {
                        continue;
                    }

                    // Scope Check
                    if self.is_in_scope(&new_url_str) {
                         if !self.crawl_discovered.contains(&new_url_str) {
                             self.crawl_discovered.insert(new_url_str.clone());
                             self.crawl_results.push(new_url_str.clone());
                             
                             // Only queue if active and hostname matches (Stay on site)
                             if self.crawl_active {
                                 if let Some(target_host) = Url::parse(&self.crawl_target).ok().and_then(|u| u.host_str().map(|s| s.to_string())) {
                                     if let Some(url_host) = new_url.host_str() {
                                         if url_host == target_host {
                                             self.crawl_queue.push_back(new_url_str);
                                         }
                                     }
                                 }
                             }
                         }
                    }
                }
            }
        }
    }

    fn run_scanner_step(&mut self) {
        if !self.scanner_active { return; }
        if self.pending_scans.len() > 5 { return; }

        if let Some(target_url) = self.scanner_queue.pop_front() {
             if let Ok(parsed_base) = Url::parse(&target_url) {
                 let pairs: Vec<(String, String)> = parsed_base.query_pairs().into_owned().collect();
                 
                 for (i, (_key, val)) in pairs.iter().enumerate() {
                     // 1. SQLi Probe
                     let mut sqli_url = parsed_base.clone();
                     let mut sqli_pairs = pairs.clone();
                     sqli_pairs[i].1 = format!("{}'", val); 
                     sqli_url.query_pairs_mut().clear().extend_pairs(sqli_pairs);
                     
                     let id = self.scan_id_counter; 
                     self.scan_id_counter += 1;
                     self.pending_scans.insert(id, (target_url.clone(), "SQLi".into()));
                     
                     let _ = self.tx_command.send(NodeCommand::SendRequest {
                        id, method: "GET".into(), url: sqli_url.to_string(), headers: serde_json::Value::Null, body: None 
                     });

                     // 2. XSS Probe
                     let mut xss_url = parsed_base.clone();
                     let mut xss_pairs = pairs.clone();
                     let payload = "<script>alert(999)</script>"; 
                     xss_pairs[i].1 = payload.to_string();
                     xss_url.query_pairs_mut().clear().extend_pairs(xss_pairs);

                     let id2 = self.scan_id_counter;
                     self.scan_id_counter += 1;
                     self.pending_scans.insert(id2, (target_url.clone(), "XSS".into()));

                      let _ = self.tx_command.send(NodeCommand::SendRequest {
                        id: id2, method: "GET".into(), url: xss_url.to_string(), headers: serde_json::Value::Null, body: None 
                     });
                 }
             }
        }
    }

    fn run_crawler_step(&mut self) {
        if !self.crawl_active { return; }
        
        // Simple throttling: 1 request every few ticks
        // In real app use SystemTime, here just a counter or reliance on update loop speed
        // self.crawl_timer += 0.1; 
        // if self.crawl_timer < 1.0 { return; }
        // self.crawl_timer = 0.0;
        
        if let Some(url) = self.crawl_queue.pop_front() {
             self.logs.push(format!("[Crawler] Visiting: {}", url));
             self.crawl_current_url = url.clone();
             let _ = self.tx_command.send(NodeCommand::NAVIGATE { url });
             self.crawl_idle_timer = 0.0; // Reset idle timer since we just did work
        } else {
             // Queue empty
             self.crawl_current_url = "Waiting for queue...".to_string();
        }
    }

    fn run_intruder_step(&mut self) {
        if !self.intr_running { return; }
        
        let payloads: Vec<&str> = self.intr_payloads.split('\n').filter(|s| !s.is_empty()).collect();
        if self.intr_current_idx >= payloads.len() {
            self.intr_running = false;
            self.logs.push("Intruder attack finished.".into());
            return;
        }

        let payload = payloads[self.intr_current_idx];
        let body = self.intr_body_template.replace("§payload§", payload);

        // Map ID 90000 + idx for internal tracking
        let id_proxy = 90000 + self.intr_current_idx as u32; 
        
        let mut map = serde_json::Map::new();
        for (k, v) in &self.intr_headers {
            if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); }
        }

        self.logs.push(format!("[Intruder] Testing: {}", payload));
        let _ = self.tx_command.send(NodeCommand::SendRequest {
            id: id_proxy,
            method: self.intr_method.clone(),
            url: self.intr_url.clone(),
            headers: serde_json::Value::Object(map),
            body: Some(body),
        });
        
        self.intr_current_idx += 1;
    }

    fn save_project(&mut self) {
        let project = VantaProject {
            history: self.history.clone(),
            scope_domains: self.scope_domains.clone(),
            crawl_results: self.crawl_results.clone(),
            crawl_vulnerabilities: self.crawl_vulnerabilities.clone(),
            crawl_target: self.crawl_target.clone(),
            scanner_findings: self.scanner_findings.clone(),
        };

        if let Ok(json) = serde_json::to_string_pretty(&project) {
            if let Ok(_) = std::fs::write("project.json", json) {
                self.logs.push("Project saved to project.json".into());
            } else {
                self.logs.push("Error writing project.json".into());
            }
        } else {
            self.logs.push("Error serializing project".into());
        }
    }

    fn load_project(&mut self) {
        if let Ok(content) = std::fs::read_to_string("project.json") {
            if let Ok(project) = serde_json::from_str::<VantaProject>(&content) {
                self.history = project.history;
                self.scope_domains = project.scope_domains;
                self.crawl_results = project.crawl_results;
                self.crawl_vulnerabilities = project.crawl_vulnerabilities;
                self.crawl_target = project.crawl_target;
                self.scanner_findings = project.scanner_findings;
                
                // Re-hydrate discovered set for crawler
                self.crawl_discovered = self.crawl_results.iter().cloned().collect();
                
                self.logs.push("Project loaded from project.json".into());
            } else {
                 self.logs.push("Error parsing project.json".into());
            }
        } else {
            self.logs.push("project.json not found".into());
        }
    }
}


impl eframe::App for VantaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.intr_running {
             self.run_intruder_step();
             ctx.request_repaint();
        }
        if self.crawl_active {
            // Very basic throttle / scheduling
            // In a real app we'd wait for the previous page load to finish
            // here we might spam NAVIGATE commands if we are not careful
            // For this MVP, let's assume one step per update is WAY too fast.
            // Let's use a random probability or frame count to slow it down
            // or better yet, rely on user supervision.
            // Actually, let's just run it. Playwright will queue them? No, it might cancel previous nav.
            // Ideally we need a "is_navigating" flag from Node.
            // For now, let's rely on human to stop it if it goes crazy, or add a delay.
            // Let's assume 60FPS -> 1 request every 60 frames = 1 sec
             ctx.request_repaint(); // Keep loop alive
             // self.run_crawler_step(); // MOVED TO TIMER LOGIC or manual CLICK?
             
             // Let's make it so we only navigate if we have items.
             // To prevent instant spam, we need a timer.
             // Since I don't have delta_time easily here without more code,
             // I'll add a simple counter logic to the struct if I could, but I can't easily add fields now.
             // Wait, I added crawl_timer!
             self.crawl_timer += 0.016; // approximate 60fps
             if self.crawl_timer > 2.0 { // 2 seconds delay between crawls
                 self.run_crawler_step();
                 self.crawl_timer = 0.0;
             }
             
             // Auto-stop logic
             if self.crawl_queue.is_empty() {
                 self.crawl_idle_timer += 0.016;
                 if self.crawl_idle_timer > 5.0 {
                     self.crawl_active = false;
                     self.show_report = true;
                     self.logs.push("[Crawler] Scan finished (Idle timeout).".into());
                     self.crawl_current_url = "Finished".into();
                 }
             }
        }

        // Active Scanner Step
        if self.scanner_active {
            self.run_scanner_step();
        }

        while let Ok(event) = self.rx_event.try_recv() {
            match event {
                NodeEvent::READY => self.logs.push("Backend Ready.".into()),
                NodeEvent::LOG { message } => self.logs.push(format!("[Log] {}", message)),
                
                NodeEvent::RequestIntercepted { id, method, url, headers, body } => {
                     // DB Persistence
                     self.conn.execute(
                        "INSERT OR REPLACE INTO history (id, method, url, status, length, p_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![id, method, url, "Pending", 0, "Request"],
                     ).ok();

                     self.history.push(HistoryItem {
                        id,
                        method: method.clone(),
                        url: url.clone(),
                        status: "Pending".to_string(),
                    });

                    let in_scope = self.is_in_scope(&url);
                    
                    // If Crawling or Intercept Disabled, we move on.
                    // IMPORTANT: If Crawling, we FORCE intercept_response to true so we can scan the body.
                    if self.crawl_active {
                        let _ = self.tx_command.send(NodeCommand::CONTINUE {
                            id, method, headers, body, intercept_response: true,
                        });
                        self.logs.push(format!("[Crawler] Auto-Fwd Req: {}", url));
                    } else if !self.intercept_enabled || !in_scope {
                        let _ = self.tx_command.send(NodeCommand::CONTINUE {
                            id, method, headers, body, intercept_response: self.intercept_responses && in_scope,
                        });
                        if in_scope { self.logs.push(format!("[Auto-Fwd] {}", url)); }
                    } else {
                        self.logs.push(format!("[Queueing Req] {} {}", method, url));
                        self.queue.push_back(InterceptItem::Request(InterceptedRequest {
                            id, method, url, headers, body
                        }));
                        ctx.request_repaint();
                    }
                },
                
                NodeEvent::ResponseIntercepted { id, status, headers, body } => {
                      if self.crawl_active {
                          self.scan_content(&body);
                          // Auto-fulfill response to keep crawler moving
                           let _ = self.tx_command.send(NodeCommand::FulfillResponse {
                                id, status, headers: headers.clone(), body: body.clone()
                            });
                            // We do NOT queue it for UI.
                            // Update history logic
                             if let Some(item) = self.history.iter_mut().find(|h| h.id == id) {
                                item.status = format!("{} (Scanned)", status);
                                // Update DB
                                self.conn.execute("UPDATE history SET status = ?1 WHERE id = ?2", params![item.status, id]).ok();
                             }
                            ctx.request_repaint();
                            return; // Skip queueing
                      }

                      if let Some(item) = self.history.iter_mut().find(|h| h.id == id) {
                         item.status = format!("{} (Intercepted)", status);
                         // Update DB
                         self.conn.execute("UPDATE history SET status = ?1 WHERE id = ?2", params![item.status, id]).ok();
                     } else {
                         // Edge case: Response without Request?
                         self.history.push(HistoryItem {
                             id,
                             method: "RESP".to_string(),
                             url: "Unknown".to_string(),
                             status: status.to_string(),
                         });
                     }
                     
                     // Bug fix: Only queue if we actually care (implied by the fact we got here? 
                     // No, if we didn't ask for interception we wouldn't be here. 
                     // But let's be safe and just show it.)
                     self.logs.push(format!("[Queueing Resp] Status {}", status));
                     self.queue.push_back(InterceptItem::Response(InterceptedResponse {
                        id, status, headers, body
                     }));
                     ctx.request_repaint();
                },

                NodeEvent::RepeaterResponse { id, status, headers: _, body } => {
                    if id >= 90000 {
                         let idx = (id - 90000) as usize;
                         let payloads: Vec<&str> = self.intr_payloads.split('\n').filter(|s| !s.is_empty()).collect();
                         if let Some(payload) = payloads.get(idx) {
                             self.intr_results.push(IntruderResult {
                                 payload: payload.to_string(),
                                 status: status,
                                 length: body.len(),
                             });
                         }
                    } else {
                        self.rep_response = format!("Status: {}\n\n{}", status, body);
                        self.logs.push("Repeater response received.".into());
                    }
                    ctx.request_repaint();
                }
            }
        }

        // Poll Async Intruder Results
        while let Ok(res) = self.rx_intruder_result.try_recv() {
            match res {
                AsyncIntruderResult::Progress { idx: _, payload, status, length } => {
                    self.intr_results.push(IntruderResult { payload, status, length });
                },
                AsyncIntruderResult::Finished => {
                    self.intr_running = false;
                    self.logs.push("[Intruder] Attack Finished.".into());
                }
            }
        }
        
        // Poll Async Recon Results
        while let Ok(res) = self.rx_recon_result.try_recv() {
            match res {
                AsyncReconResult::Found { subdomain, ip } => {
                     self.recon_results.push((subdomain.clone(), ip.clone()));
                     self.logs.push(format!("[Recon] Found: {} -> {}", subdomain, ip));
                },
                AsyncReconResult::Finished => {
                    self.recon_running = false; // We don't actually emit Finished yet in the async loop above, need to add it!
                }
            }
        }
        
        // Poll Async Port Scan Results
        while let Ok(res) = self.rx_portscan_result.try_recv() {
            match res {
                AsyncPortScanResult::Open { port, service } => {
                     self.portscan_results.push((port, service.clone()));
                     self.logs.push(format!("[PortScan] Open: {} ({})", port, service));
                },
                AsyncPortScanResult::Finished => {
                    self.portscan_running = false;
                }
            }
        }
        
        // Poll Async Active Scan Results
        while let Ok(res) = self.rx_activescan_result.try_recv() {
            match res {
                AsyncActiveScanResult::Finding(finding) => {
                     self.logs.push(format!("[ActiveScan] {} found on {}: {}", finding.severity, finding.param, finding.vuln_type));
                     self.activescan_findings.push(finding);
                },
                AsyncActiveScanResult::Progress { tested } => {
                    self.activescan_tested = tested;
                },
                AsyncActiveScanResult::Finished => {
                    self.activescan_running = false;
                }
            }
        }
        
        // Poll Sniffer Packets
        while let Ok(packet) = self.rx_sniffer.try_recv() {
            self.sniffer_packets.push(packet);
            // Keep only last 1000 packets
            if self.sniffer_packets.len() > 1000 {
                self.sniffer_packets.remove(0);
            }
        }
        self.sync_editor();

        // Keyboard Shortcuts
        // Only if Interceptor tab is active and we have a request
        if self.active_tab == Tab::Intercept && !self.queue.is_empty() {
            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::F)) {
                if let Some(item) = self.queue.pop_front() {
                    match item {
                        InterceptItem::Request(req) => {
                             let _ = self.tx_command.send(NodeCommand::CONTINUE { 
                                id: req.id,
                                method: req.method.clone(),
                                headers: req.headers.clone(),
                                body: req.body.clone(),
                                intercept_response: self.intercept_responses,
                            });
                            self.logs.push(format!("Forwarded request to {}", req.url));
                            self.history.push(HistoryItem {
                                id: req.id,
                                method: req.method.clone(),
                                url: req.url.clone(),
                                status: "Pending".into(),
                            });
                        },
                        InterceptItem::Response(res) => {
                            let _ = self.tx_command.send(NodeCommand::FulfillResponse {
                                id: res.id,
                                status: res.status,
                                headers: res.headers.clone(),
                                body: res.body.clone()
                            });
                             self.logs.push(format!("Forwarded response {}", res.status));
                             if let Some(h_item) = self.history.iter_mut().find(|h| h.id == res.id) {
                                h_item.status = res.status.to_string();
                            }
                        }
                    }
                }
            }
            
            if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::D)) {
                if let Some(item) = self.queue.pop_front() {
                    match item {
                        InterceptItem::Request(req) => {
                             let _ = self.tx_command.send(NodeCommand::DROP { id: req.id });
                        },
                        _ => {}
                    }
                    self.logs.push("Dropped packet.".into());
                }
            }
        }

        // TOP PANEL: Global Controls & Navigation
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("🕸 VantaStalker").color(egui::Color32::from_rgb(0, 255, 128)).strong()); // Green Logo
                ui.label("Pro Edition");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                     if ui.button("📂 Load").clicked() { self.load_project(); }
                     if ui.button("💾 Save").clicked() { self.save_project(); }
                     ui.separator();
                     ui.label("Target:");
                     ui.text_edit_singleline(&mut self.target_url);
                     if ui.button("🚀 Launch").clicked() {
                        self.logs.push(format!("Navigating to {}...", self.target_url));
                        let _ = self.tx_command.send(NodeCommand::NAVIGATE { url: self.target_url.clone() });
                     }
                     ui.separator();
                     ui.checkbox(&mut self.intercept_enabled, "Intercept All");
                     ui.separator();
                     // Theme Toggle
                     let icon = if self.is_dark_mode { "🌙" } else { "☀️" };
                     if ui.button(icon).clicked() {
                         self.is_dark_mode = !self.is_dark_mode;
                         Self::apply_theme(ctx, self.is_dark_mode);
                     }
                });
            });
            ui.add_space(5.0);
            ui.separator();
            ui.add_space(5.0);
            
            // NAVIGATION TABS
            ui.horizontal(|ui| {
                 ui.style_mut().spacing.item_spacing.x = 20.0; // Space out tabs
                 
                 let tab_btn = |ui: &mut egui::Ui, tab: Tab, label: &str, active: &mut Tab| {
                     let is_active = *active == tab;
                     let color = if is_active { egui::Color32::WHITE } else { egui::Color32::GRAY };
                     if ui.add(egui::Button::new(egui::RichText::new(label).color(color).size(14.0)).frame(false)).clicked() {
                         *active = tab;
                     }
                     if is_active {
                          let rect = ui.min_rect().translate(egui::vec2(0.0, 22.0));
                          let line_rect = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), 2.0));
                          ui.painter().rect_filled(
                              line_rect, 
                              0.0, 
                              egui::Color32::from_rgb(0, 255, 128)
                          );
                     }
                 };

                 tab_btn(ui, Tab::Dashboard, "📊 Dashboard", &mut self.active_tab);
                 tab_btn(ui, Tab::Intercept, "🔴 Interceptor", &mut self.active_tab);
                 tab_btn(ui, Tab::History, "📜 History", &mut self.active_tab);
                 tab_btn(ui, Tab::Repeater, "🔁 Repeater", &mut self.active_tab);
                 tab_btn(ui, Tab::Intruder, "💣 Intruder", &mut self.active_tab);
                 tab_btn(ui, Tab::Recon, "📡 Recon", &mut self.active_tab);
                 tab_btn(ui, Tab::PortScanner, "🔌 Ports", &mut self.active_tab);
                 tab_btn(ui, Tab::ActiveScanner, "🤖 Scanner", &mut self.active_tab);
                 tab_btn(ui, Tab::Sniffer, "🦈 Sniffer", &mut self.active_tab);
                 tab_btn(ui, Tab::Scope, "🎯 Scope", &mut self.active_tab);
                 tab_btn(ui, Tab::Crawler, "🕷 Crawler", &mut self.active_tab);
                 tab_btn(ui, Tab::Decoder, "🪄 Decoder", &mut self.active_tab);

                 if !self.queue.is_empty() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(format!("{} Pending", self.queue.len())).color(egui::Color32::RED).strong()); 
                    });
                 }
            });
            ui.add_space(5.0);
        });

        // BOTTOM PANEL: Logs
        egui::TopBottomPanel::bottom("bottom_panel").resizable(true).min_height(100.0).show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Terminal / Logs").small().strong());
                ui.separator();
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for log in &self.logs {
                        ui.label(egui::RichText::new(log).font(egui::FontId::monospace(12.0)));
                    }
                });
            });
        });

        // CENTRAL PANEL: Main Content
        egui::CentralPanel::default().show(ctx, |ui| {
             match self.active_tab {
                Tab::Dashboard => {
                    ui.heading("📊 Dashboard");
                    ui.label("Session overview and statistics.");
                    ui.separator();
                    
                    // Stats cards in a horizontal layout
                    ui.horizontal(|ui| {
                        // Total Requests Card
                        ui.group(|ui| {
                            ui.set_min_width(150.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("📜").size(32.0));
                                ui.heading(format!("{}", self.history.len()));
                                ui.label("Total Requests");
                            });
                        });
                        
                        // Queue Card
                        ui.group(|ui| {
                            ui.set_min_width(150.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("🔴").size(32.0));
                                ui.heading(format!("{}", self.queue.len()));
                                ui.label("Pending Queue");
                            });
                        });
                        
                        // Vulnerabilities Card
                        ui.group(|ui| {
                            ui.set_min_width(150.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("⚠️").size(32.0));
                                ui.heading(format!("{}", self.activescan_findings.len()));
                                ui.label("Vulnerabilities");
                            });
                        });
                        
                        // Subdomains Card
                        ui.group(|ui| {
                            ui.set_min_width(150.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("📡").size(32.0));
                                ui.heading(format!("{}", self.recon_results.len()));
                                ui.label("Subdomains");
                            });
                        });
                        
                        // Open Ports Card
                        ui.group(|ui| {
                            ui.set_min_width(150.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("🔌").size(32.0));
                                ui.heading(format!("{}", self.portscan_results.len()));
                                ui.label("Open Ports");
                            });
                        });
                    });
                    
                    ui.add_space(20.0);
                    ui.separator();
                    
                    // Status Code Distribution
                    ui.heading("Status Code Distribution");
                    
                    // Calculate status code counts
                    let mut status_2xx = 0;
                    let mut status_3xx = 0;
                    let mut status_4xx = 0;
                    let mut status_5xx = 0;
                    
                    for item in &self.history {
                        if let Ok(code) = item.status.parse::<u16>() {
                            match code {
                                200..=299 => status_2xx += 1,
                                300..=399 => status_3xx += 1,
                                400..=499 => status_4xx += 1,
                                500..=599 => status_5xx += 1,
                                _ => {}
                            }
                        }
                    }
                    
                    // Bar chart using egui_plot
                    use egui_plot::{Plot, Bar, BarChart};
                    
                    let bars = vec![
                        Bar::new(0.0, status_2xx as f64).name("2xx Success").fill(egui::Color32::GREEN),
                        Bar::new(1.0, status_3xx as f64).name("3xx Redirect").fill(egui::Color32::YELLOW),
                        Bar::new(2.0, status_4xx as f64).name("4xx Client Error").fill(egui::Color32::from_rgb(255, 165, 0)),
                        Bar::new(3.0, status_5xx as f64).name("5xx Server Error").fill(egui::Color32::RED),
                    ];
                    
                    let chart = BarChart::new(bars).width(0.7);
                    
                    Plot::new("status_chart")
                        .height(200.0)
                        .allow_drag(false)
                        .allow_zoom(false)
                        .show_axes([false, true])
                        .show(ui, |plot_ui| {
                            plot_ui.bar_chart(chart);
                        });
                    
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::GREEN, format!("2xx: {}", status_2xx));
                        ui.colored_label(egui::Color32::YELLOW, format!("3xx: {}", status_3xx));
                        ui.colored_label(egui::Color32::from_rgb(255, 165, 0), format!("4xx: {}", status_4xx));
                        ui.colored_label(egui::Color32::RED, format!("5xx: {}", status_5xx));
                    });
                    
                    ui.add_space(20.0);
                    ui.separator();
                    
                    // Recent Activity Log
                    ui.heading("Recent Activity");
                    egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                        for log in self.logs.iter().rev().take(10) {
                            ui.label(log);
                        }
                    });
                },
                Tab::Intercept => {
                     if let Some(item_clone) = self.queue.front().cloned() {
                        ui.group(|ui| {
                            ui.add_space(5.0);
                            match item_clone {
                                InterceptItem::Request(ref req) => {
                                    ui.heading("🔴 Intercepted Request");
                                    ui.label(egui::RichText::new(&req.url).strong());
                                    ui.horizontal(|ui| {
                                        ui.label("Method:");
                                    egui::ComboBox::from_id_salt("method_combo").selected_text(&self.edit_method).show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.edit_method, "GET".to_string(), "GET");
                                            ui.selectable_value(&mut self.edit_method, "POST".to_string(), "POST");
                                            ui.selectable_value(&mut self.edit_method, "PUT".to_string(), "PUT");
                                            ui.selectable_value(&mut self.edit_method, "DELETE".to_string(), "DELETE");
                                        });
                                    });
                                },
                                InterceptItem::Response(ref _res) => {
                                     ui.heading("🔵 Intercepted Response");
                                     ui.horizontal(|ui| { ui.label("New Status:"); ui.text_edit_singleline(&mut self.edit_status); });
                                }
                            }
                            
                            ui.label("Headers:");
                            egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                                let mut remove_idx = None;
                                for (i, (k, v)) in self.edit_headers.iter_mut().enumerate() {
                                    ui.horizontal(|ui| { ui.text_edit_singleline(k); ui.text_edit_singleline(v); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
                                }
                                if let Some(i) = remove_idx { self.edit_headers.remove(i); }
                                if ui.button("➕ Add Header").clicked() { self.edit_headers.push(("".to_string(), "".to_string())); }
                            });

                            ui.label("Body:");
                            ui.text_edit_multiline(&mut self.edit_body);

                            ui.horizontal(|ui| {
                                if ui.button("▶ Forward").clicked() {
                                     let mut map = serde_json::Map::new();
                                    for (k, v) in &self.edit_headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
                                    let new_headers = serde_json::Value::Object(map);

                                    match item_clone {
                                        InterceptItem::Request(ref req) => {
                                            let _ = self.tx_command.send(NodeCommand::CONTINUE { id: req.id, method: self.edit_method.clone(), headers: new_headers, body: if self.edit_body.is_empty() { None } else { Some(self.edit_body.clone()) }, intercept_response: self.intercept_responses });
                                        },
                                        InterceptItem::Response(ref res) => {
                                            let status = self.edit_status.parse::<u16>().unwrap_or(res.status);
                                            let _ = self.tx_command.send(NodeCommand::FulfillResponse { id: res.id, status, headers: new_headers, body: self.edit_body.clone() });
                                        }
                                    }
                                    self.queue.pop_front();
                                    self.editor_loaded_id = None; 
                                }
                                if ui.button("❌ Drop").clicked() {
                                    let id = match item_clone { InterceptItem::Request(ref r) => r.id, InterceptItem::Response(ref r) => r.id };
                                    let _ = self.tx_command.send(NodeCommand::DROP { id });
                                    self.queue.pop_front();
                                    self.editor_loaded_id = None; 
                                }
                            });
                        });
                    } else {
                         ui.label("Waiting for traffic...");
                    }
                },
                Tab::History => {
                    use egui_extras::{TableBuilder, Column};
                    
                    ui.horizontal(|ui| {
                        ui.heading("📜 Request History");
                        ui.separator();
                        
                        if ui.button("📤 Export CSV").clicked() {
                            if let Some(path) = FileDialog::new()
                                .add_filter("CSV", &["csv"])
                                .set_file_name("history.csv")
                                .save_file() 
                            {
                                let mut csv = String::from("ID,Method,URL,Status\n");
                                for item in &self.history {
                                    csv.push_str(&format!("{},{},{},{}\n", 
                                        item.id, item.method, item.url, item.status));
                                }
                                if std::fs::write(&path, csv).is_ok() {
                                    self.logs.push(format!("[Export] Saved {} items to CSV", self.history.len()));
                                }
                            }
                        }
                        
                        if ui.button("📤 Export JSON").clicked() {
                            if let Some(path) = FileDialog::new()
                                .add_filter("JSON", &["json"])
                                .set_file_name("history.json")
                                .save_file() 
                            {
                                if let Ok(json) = serde_json::to_string_pretty(&self.history) {
                                    if std::fs::write(&path, json).is_ok() {
                                        self.logs.push(format!("[Export] Saved {} items to JSON", self.history.len()));
                                    }
                                }
                            }
                        }
                        
                        ui.label(format!("{} requests", self.history.len()));
                    });
                    
                    ui.separator();
                    
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::auto().resizable(true)) // ID
                        .column(Column::auto().resizable(true)) // Method
                        .column(Column::remainder())            // URL (takes rest of space)
                        .column(Column::auto().resizable(true)) // Status
                        .header(20.0, |mut header| {
                            header.col(|ui| { ui.strong("ID"); });
                            header.col(|ui| { ui.strong("Method"); });
                            header.col(|ui| { ui.strong("URL"); });
                            header.col(|ui| { ui.strong("Status"); });
                        })
                        .body(|mut body| {
                            for item in &self.history {
                                body.row(18.0, |mut row| {
                                    row.col(|ui| { ui.label(item.id.to_string()); });
                                    row.col(|ui| { ui.label(&item.method); });
                                    row.col(|ui| { ui.label(&item.url); }); // Too long URLs might need truncation or scroll
                                    row.col(|ui| { 
                                         // Status color coding
                                        let color = if item.status.starts_with("2") { egui::Color32::GREEN } 
                                                    else if item.status.starts_with("3") { egui::Color32::YELLOW }
                                                    else if item.status.starts_with("4") || item.status.starts_with("5") { egui::Color32::RED }
                                                    else { egui::Color32::GRAY };
                                        ui.colored_label(color, &item.status);
                                    });
                                });
                            }
                        });
                },
                Tab::Repeater => {
                     ui.columns(2, |columns| {
                        columns[0].vertical(|ui| {
                            ui.heading("Request");
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_salt("rep_method_combo").selected_text(&self.rep_method).show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.rep_method, "GET".to_string(), "GET");
                                    ui.selectable_value(&mut self.rep_method, "POST".to_string(), "POST");
                                    ui.selectable_value(&mut self.rep_method, "PUT".to_string(), "PUT");
                                    ui.selectable_value(&mut self.rep_method, "DELETE".to_string(), "DELETE");
                                });
                                ui.text_edit_singleline(&mut self.rep_url);
                            });
                             ui.label("Headers:");
                            egui::ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                                let mut remove_idx = None;
                                for (i, (k, v)) in self.rep_headers.iter_mut().enumerate() {
                                    ui.horizontal(|ui| { ui.text_edit_singleline(k); ui.text_edit_singleline(v); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
                                }
                                if let Some(i) = remove_idx { self.rep_headers.remove(i); }
                                if ui.button("➕ Add Header").clicked() { self.rep_headers.push(("".to_string(), "".to_string())); }
                            });
                            ui.label("Body:");
                            ui.text_edit_multiline(&mut self.rep_body);
                            if ui.button("▶ Send Request").clicked() { 
                                let mut map = serde_json::Map::new();
                                for (k, v) in &self.rep_headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
                                let _ = self.tx_command.send(NodeCommand::SendRequest { id: 0, method: self.rep_method.clone(), url: self.rep_url.clone(), headers: serde_json::Value::Object(map), body: if self.rep_body.is_empty() { None } else { Some(self.rep_body.clone()) } });
                                self.rep_response = "Sending...".into();
                            }
                        });
                        columns[1].vertical(|ui| { ui.heading("Response"); ui.text_edit_multiline(&mut self.rep_response); });
                     });
                },
                Tab::Scope => {
                    ui.heading("🎯 Scope Configuration");
                    ui.label("Define a list of domains. Interceptor will only stop requests that contain these strings.");
                    ui.horizontal(|ui| {
                        ui.label("Add Domain:");
                        ui.text_edit_singleline(&mut self.new_scope_domain);
                        if ui.button("Add").clicked() && !self.new_scope_domain.is_empty() {
                            self.scope_domains.push(self.new_scope_domain.clone());
                            self.new_scope_domain.clear();
                        }
                    });
                     egui::ScrollArea::vertical().show(ui, |ui| {
                        let mut remove_idx = None;
                        for (i, domain) in self.scope_domains.iter().enumerate() {
                            ui.horizontal(|ui| { ui.label(format!("• {}", domain)); if ui.button("🗑").clicked() { remove_idx = Some(i); } });
                        }
                        if let Some(i) = remove_idx { self.scope_domains.remove(i); }
                    });
                },
                Tab::Intruder => {
                    ui.columns(2, |columns| {
                        columns[0].vertical(|ui| {
                            ui.heading("Attack Configuration");
                            ui.label("Target URL:");
                            ui.text_edit_singleline(&mut self.intr_url);
                            
                            ui.label("Body Template (Use §payload§ marker):");
                            ui.text_edit_multiline(&mut self.intr_body_template);

                            ui.label("Payloads (One per line):");
                            ui.horizontal(|ui| {
                                ui.label("Payloads (One per line):");
                                if ui.button("📂 Load Wordlist...").clicked() {
                                    if let Some(path) = FileDialog::new().pick_file() {
                                        if let Ok(content) = std::fs::read_to_string(path) {
                                            self.intr_payloads = content;
                                        }
                                    }
                                }
                            });
                            
                            // Transform Controls
                            ui.horizontal(|ui| {
                                egui::ComboBox::from_id_salt("intr_transform")
                                    .selected_text(format!("{:?}", self.intr_transform))
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.intr_transform, PayloadTransform::Identity, "Identity (None)");
                                        ui.selectable_value(&mut self.intr_transform, PayloadTransform::Base64, "Base64 Encode");
                                        ui.selectable_value(&mut self.intr_transform, PayloadTransform::MD5, "MD5 Hash");
                                    });
                                
                                if ui.button("⚡ Apply Transform (Rayon)").clicked() {
                                    let lines: Vec<String> = self.intr_payloads.lines().map(|s| s.to_string()).collect();
                                    let transform = self.intr_transform;

                                    // Rayon Parallel Processing
                                    let processed: Vec<String> = lines.par_iter().map(|line| {
                                        match transform {
                                            PayloadTransform::Identity => line.clone(),
                                            PayloadTransform::Base64 => BASE64_STANDARD.encode(line),
                                            PayloadTransform::MD5 => {
                                                use md5::Digest;
                                                let digest = Md5::digest(line.as_bytes());
                                                format!("{:x}", digest)
                                            }
                                        }
                                    }).collect();

                                    self.intr_payloads = processed.join("\n");
                                }
                            });

                            ui.text_edit_multiline(&mut self.intr_payloads);
                            
                            ui.separator();
                            ui.horizontal(|ui| {
                                ui.label("Attack Engine:");
                                egui::ComboBox::from_id_salt("intr_mode_combo")
                                    .selected_text(match self.intr_mode {
                                        IntruderMode::Native => "🚀 Native (Rust/Tokio)",
                                        IntruderMode::Browser => "🐢 Browser (Node/Playwright)",
                                    })
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.intr_mode, IntruderMode::Native, "🚀 Native (Rust/Tokio)");
                                        ui.selectable_value(&mut self.intr_mode, IntruderMode::Browser, "🐢 Browser (Node/Playwright)");
                                    });
                            });
                            ui.label(egui::RichText::new(match self.intr_mode {
                                IntruderMode::Native => "Fast. Direct HTTP. No session context.",
                                IntruderMode::Browser => "Slower. Uses Browser Context (Cookies, Auth).",
                            }).small().italics());

                            ui.add_space(10.0);

                            if self.intr_running {
                                if ui.button("⏹ Stop Attack").clicked() { 
                                    self.intr_running = false; 
                                }
                                ui.spinner();
                            } else {
                                if ui.button("💣 Start Attack").clicked() {
                                    self.intr_running = true;
                                    self.intr_current_idx = 0;
                                    self.intr_results.clear();
                                    self.logs.push(format!("Starting Intruder Attack ({:?})...", self.intr_mode));
                                    
                                    // Parse payloads
                                    let payloads: Vec<String> = self.intr_payloads.lines().map(|s| s.to_string()).collect();
                                    let headers: Vec<(String, String)> = self.intr_headers.iter()
                                        .map(|(k,v)| (k.clone(), v.clone()))
                                        .collect();

                                    match self.intr_mode {
                                        IntruderMode::Native => {
                                             let job = AsyncIntruderJob {
                                                url: self.intr_url.clone(),
                                                method: self.intr_method.clone(),
                                                headers,
                                                body_template: self.intr_body_template.clone(),
                                                payloads,
                                            };
                                            let _ = self.tx_intruder_job.send(job);
                                        },
                                        IntruderMode::Browser => {
                                            // Legacy Loop: Send individual requests to Node
                                            // Warning: This loop blocks the UI thread if we do it all at once!
                                            // We should probably spawn a thread or just send them all to the queue?
                                            // Sending 1000 IPC messages is fast, Node will queue them.
                                            
                                            // We need a way to track these specifically as Intruder requests in Node?
                                            // Or we just use SendRequest and listen for traffic?
                                            // For now, let's just fire them.
                                            let template = self.intr_body_template.clone();
                                            let tx = self.tx_command.clone();
                                            let url = self.intr_url.clone();
                                            let method = self.intr_method.clone();
                                            
                                            // Spawn a small thread to not freeze UI while queuing
                                            thread::spawn(move || {
                                                for (i, p) in payloads.iter().enumerate() {
                                                    let body = template.replace("§payload§", p);
                                                    let mut map = serde_json::Map::new();
                                                    for (k, v) in &headers { if !k.is_empty() { map.insert(k.clone(), serde_json::Value::String(v.clone())); } }
                                                    
                                                    // Start ID at 90000+i to distinguish? Or just use 0 (Node auto-assigns?)
                                                    // Using 0 tells Node it's a new request.
                                                    let _ = tx.send(NodeCommand::SendRequest { 
                                                        id: 0, 
                                                        method: method.clone(), 
                                                        url: url.clone(), 
                                                        headers: serde_json::Value::Object(map), 
                                                        body: if body.is_empty() { None } else { Some(body) } 
                                                    });
                                                    
                                                    // Small delay to prevent IPC explosion
                                                    if i % 10 == 0 { thread::sleep(std::time::Duration::from_millis(5)); }
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        });

                        columns[1].vertical(|ui| {
                            ui.heading("Attack Results");
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                egui::Grid::new("intruder_grid").striped(true).show(ui, |ui| {
                                    ui.label(egui::RichText::new("Payload").strong());
                                    ui.label(egui::RichText::new("Status").strong());
                                    ui.label(egui::RichText::new("Length").strong());
                                    ui.end_row();

                                    for res in &self.intr_results {
                                        ui.label(&res.payload);
                                        match res.status {
                                            200..=299 => { ui.label(egui::RichText::new(res.status.to_string()).color(egui::Color32::GREEN)); },
                                            300..=399 => { ui.label(egui::RichText::new(res.status.to_string()).color(egui::Color32::YELLOW)); },
                                            _ => { ui.label(egui::RichText::new(res.status.to_string()).color(egui::Color32::RED)); }
                                        }
                                        ui.label(res.length.to_string());
                                        ui.end_row();
                                    }
                                });
                            });
                        });
                    });
                },
                Tab::Recon => {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.heading("DNS Subdomain Enumeration (Recon)");
                        ui.separator();
                        
                        ui.horizontal(|ui| {
                            ui.label("Root Domain:");
                            ui.text_edit_singleline(&mut self.recon_domain);
                        });
                        
                        ui.add_space(5.0);
                        ui.label("Wordlist (Subdomains):");
                        ui.horizontal(|ui| {
                             if ui.button("📂 Load Wordlist").clicked() {
                                if let Some(path) = FileDialog::new().pick_file() {
                                    if let Ok(content) = std::fs::read_to_string(path) {
                                        self.recon_wordlist = content;
                                    }
                                }
                             }
                             if ui.button("Start Recon 🚀").clicked() && !self.recon_running {
                                 self.recon_running = true;
                                 self.recon_results.clear();
                                 let domain = self.recon_domain.clone();
                                 let wordlist: Vec<String> = self.recon_wordlist.lines().map(|s| s.to_string()).collect();
                                 
                                 let _ = self.tx_recon_job.send(AsyncReconJob { domain, wordlist });
                                 self.logs.push("[Recon] Started DNS enumeration...".into());
                             }
                        });
                        ui.text_edit_multiline(&mut self.recon_wordlist);
                        
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.heading(format!("Results ({})", self.recon_results.len()));
                            if ui.button("📤 Export TXT").clicked() {
                                if let Some(path) = FileDialog::new()
                                    .add_filter("TXT", &["txt"])
                                    .set_file_name("subdomains.txt")
                                    .save_file() 
                                {
                                    let content = self.recon_results.iter().map(|(d, ip)| format!("{} - {}", d, ip)).collect::<Vec<_>>().join("\n");
                                    if std::fs::write(&path, content).is_ok() {
                                        self.logs.push(format!("[Export] Saved {} subdomains to TXT", self.recon_results.len()));
                                    }
                                }
                            }
                        });
                        
                        TableBuilder::new(ui)
                            .column(Column::initial(300.0).resizable(true))
                            .column(Column::remainder())
                            .header(20.0, |mut header| {
                                header.col(|ui| { ui.strong("Subdomain"); });
                                header.col(|ui| { ui.strong("IP Address"); });
                            })
                            .body(|mut body| {
                                for (sub, ip) in &self.recon_results {
                                    body.row(18.0, |mut row| {
                                        row.col(|ui| { ui.label(sub); });
                                        row.col(|ui| { ui.label(ip); });
                                    });
                                }
                            });
                    });
                },
                Tab::PortScanner => {
                    ui.heading("🔌 Port Scanner");
                    ui.label("Scan open ports on a target host. Detects common services.");
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        ui.label("Target IP/Host:");
                        ui.text_edit_singleline(&mut self.portscan_target);
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Port Range:");
                        ui.text_edit_singleline(&mut self.portscan_port_range);
                        ui.label("(e.g., 1-1000 or 22,80,443,3306)");
                    });
                    
                    ui.horizontal(|ui| {
                        if self.portscan_running {
                            ui.spinner();
                            ui.label(format!("Scanning... {} open ports found", self.portscan_results.len()));
                        } else {
                            if ui.button("🚀 Start Scan").clicked() {
                                self.portscan_running = true;
                                self.portscan_results.clear();
                                let target = self.portscan_target.clone();
                                
                                // Parse port range
                                let ports: Vec<u16> = if self.portscan_port_range.contains('-') {
                                    let parts: Vec<&str> = self.portscan_port_range.split('-').collect();
                                    if parts.len() == 2 {
                                        let start: u16 = parts[0].trim().parse().unwrap_or(1);
                                        let end: u16 = parts[1].trim().parse().unwrap_or(1000);
                                        (start..=end).collect()
                                    } else {
                                        (1..=1000).collect()
                                    }
                                } else {
                                    self.portscan_port_range.split(',')
                                        .filter_map(|s| s.trim().parse().ok())
                                        .collect()
                                };
                                
                                let _ = self.tx_portscan_job.send(AsyncPortScanJob { target, ports });
                                self.logs.push("[PortScan] Started port scanning...".into());
                            }
                            
                            if ui.button("📋 Top 100 Ports").clicked() {
                                self.portscan_port_range = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443".into();
                            }
                        }
                    });
                    
                    ui.separator();
                    ui.heading(format!("Open Ports ({})", self.portscan_results.len()));
                    
                    // Sort results by port number
                    let mut sorted_results = self.portscan_results.clone();
                    sorted_results.sort_by_key(|(port, _)| *port);
                    
                    egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                        TableBuilder::new(ui)
                            .column(Column::initial(100.0).resizable(true))
                            .column(Column::initial(150.0).resizable(true))
                            .column(Column::remainder())
                            .header(20.0, |mut header| {
                                header.col(|ui| { ui.strong("Port"); });
                                header.col(|ui| { ui.strong("Service"); });
                                header.col(|ui| { ui.strong("Status"); });
                            })
                            .body(|mut body| {
                                for (port, service) in &sorted_results {
                                    body.row(18.0, |mut row| {
                                        row.col(|ui| { ui.label(format!("{}", port)); });
                                        row.col(|ui| { ui.label(service); });
                                        row.col(|ui| { ui.colored_label(egui::Color32::GREEN, "OPEN"); });
                                    });
                                }
                            });
                    });
                },
                Tab::ActiveScanner => {
                    ui.heading("🤖 Active Scanner");
                    ui.label("Automatically test for SQL Injection, XSS, Command Injection, and SSRF.");
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        ui.label("Target URL with params:");
                        ui.text_edit_singleline(&mut self.activescan_target_url);
                    });
                    
                    ui.horizontal(|ui| {
                        if self.activescan_running {
                            ui.spinner();
                            ui.label(format!("Scanning... {} findings", self.activescan_findings.len()));
                        } else {
                            if ui.button("🚀 Start Scan").clicked() {
                                self.activescan_running = true;
                                self.activescan_findings.clear();
                                self.activescan_tested = 0;
                                
                                // Parse URL and extract params
                                if let Ok(parsed) = url::Url::parse(&self.activescan_target_url) {
                                    for (key, value) in parsed.query_pairs() {
                                        let job = AsyncActiveScanJob {
                                            url: self.activescan_target_url.clone(),
                                            param: key.to_string(),
                                            original_value: value.to_string(),
                                        };
                                        let _ = self.tx_activescan_job.send(job);
                                    }
                                    self.logs.push("[ActiveScan] Started vulnerability scanning...".into());
                                } else {
                                    self.logs.push("[ActiveScan] Invalid URL!".into());
                                    self.activescan_running = false;
                                }
                            }
                            
                            if ui.button("📋 Example URL").clicked() {
                                self.activescan_target_url = "http://testphp.vulnweb.com/listproducts.php?cat=1".into();
                            }
                        }
                    });
                    
                    ui.separator();
                    ui.heading(format!("Findings ({})", self.activescan_findings.len()));
                    
                    egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                        TableBuilder::new(ui)
                            .column(Column::initial(80.0).resizable(true))
                            .column(Column::initial(120.0).resizable(true))
                            .column(Column::initial(80.0).resizable(true))
                            .column(Column::initial(200.0).resizable(true))
                            .column(Column::remainder())
                            .header(20.0, |mut header| {
                                header.col(|ui| { ui.strong("Severity"); });
                                header.col(|ui| { ui.strong("Type"); });
                                header.col(|ui| { ui.strong("Param"); });
                                header.col(|ui| { ui.strong("Payload"); });
                                header.col(|ui| { ui.strong("URL"); });
                            })
                            .body(|mut body| {
                                for finding in &self.activescan_findings {
                                    body.row(20.0, |mut row| {
                                        row.col(|ui| { 
                                            let color = match finding.severity.as_str() {
                                                "CRITICAL" => egui::Color32::from_rgb(220, 20, 60),
                                                "HIGH" => egui::Color32::from_rgb(255, 69, 0),
                                                "MEDIUM" => egui::Color32::from_rgb(255, 165, 0),
                                                _ => egui::Color32::from_rgb(255, 255, 0),
                                            };
                                            ui.colored_label(color, &finding.severity); 
                                        });
                                        row.col(|ui| { ui.label(&finding.vuln_type); });
                                        row.col(|ui| { ui.label(&finding.param); });
                                        row.col(|ui| { ui.label(&finding.payload); });
                                        row.col(|ui| { ui.label(&finding.url); });
                                    });
                                }
                            });
                    });
                },
                Tab::Sniffer => {
                    ui.heading("🦈 Packet Sniffer");
                    ui.label("Capture raw network packets (requires sudo/root).");
                    
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.label("Interface:");
                        
                        // Get available interfaces
                        let interfaces: Vec<String> = pnet::datalink::interfaces()
                            .into_iter()
                            .map(|iface| iface.name)
                            .collect();
                        
                        egui::ComboBox::from_id_salt("interface_select")
                            .selected_text(&self.sniffer_interface)
                            .show_ui(ui, |ui| {
                                for iface in &interfaces {
                                    ui.selectable_value(&mut self.sniffer_interface, iface.clone(), iface);
                                }
                            });
                        
                        ui.text_edit_singleline(&mut self.sniffer_interface);                        
                        if self.sniffer_running {
                            if ui.button("⏹ Stop").clicked() {
                                self.sniffer_running = false;
                                self.sniffer_stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                                self.logs.push("[Sniffer] Stopped capture.".into());
                            }
                            ui.spinner();
                            ui.label(format!("{} packets captured", self.sniffer_packets.len()));
                        } else {
                            if ui.button("🚀 Start Capture").clicked() {
                                self.sniffer_running = true;
                                self.sniffer_packets.clear();
                                self.sniffer_stop_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                                
                                let interface_name = self.sniffer_interface.clone();
                                let (tx, rx) = mpsc::channel::<CapturedPacket>();
                                self.rx_sniffer = rx;
                                let stop_flag = self.sniffer_stop_flag.clone();
                                
                                thread::spawn(move || {
                                    use pnet::datalink::{self, Channel::Ethernet};
                                    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
                                    use pnet::packet::ipv4::Ipv4Packet;
                                    use pnet::packet::ipv6::Ipv6Packet;
                                    use pnet::packet::tcp::TcpPacket;
                                    use pnet::packet::udp::UdpPacket;
                                    use pnet::packet::Packet;
                                    
                                    let interfaces = datalink::interfaces();
                                    let interface = interfaces
                                        .into_iter()
                                        .find(|iface| iface.name == interface_name)
                                        .unwrap_or_else(|| {
                                            let all = datalink::interfaces();
                                            all.into_iter().next().unwrap()
                                        });
                                    
                                    let (_, mut rx_link) = match datalink::channel(&interface, Default::default()) {
                                        Ok(Ethernet(_tx, rx)) => (_tx, rx),
                                        Ok(_) => return,
                                        Err(_) => return,
                                    };
                                    
                                    while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                                        if let Ok(packet_data) = rx_link.next() {
                                            if let Some(eth) = EthernetPacket::new(packet_data) {
                                                let (src_ip, dst_ip, protocol, info) = match eth.get_ethertype() {
                                                    EtherTypes::Ipv4 => {
                                                        if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                                            let proto = format!("{:?}", ipv4.get_next_level_protocol());
                                                            let info = match ipv4.get_next_level_protocol().0 {
                                                                6 => TcpPacket::new(ipv4.payload())
                                                                    .map(|tcp| format!("TCP {}→{}", tcp.get_source(), tcp.get_destination()))
                                                                    .unwrap_or_default(),
                                                                17 => UdpPacket::new(ipv4.payload())
                                                                    .map(|udp| format!("UDP {}→{}", udp.get_source(), udp.get_destination()))
                                                                    .unwrap_or_default(),
                                                                _ => String::new(),
                                                            };
                                                            (ipv4.get_source().to_string(), ipv4.get_destination().to_string(), proto, info)
                                                        } else {
                                                            continue;
                                                        }
                                                    },
                                                    EtherTypes::Ipv6 => {
                                                        if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                                                            (ipv6.get_source().to_string(), ipv6.get_destination().to_string(), "IPv6".into(), String::new())
                                                        } else {
                                                            continue;
                                                        }
                                                    },
                                                    _ => continue,
                                                };
                                                
                                                let captured = CapturedPacket {
                                                    timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                                                    src_ip,
                                                    dst_ip,
                                                    protocol,
                                                    length: packet_data.len(),
                                                    info,
                                                };
                                                let _ = tx.send(captured);
                                            }
                                        }
                                    }
                                });
                                
                                self.logs.push(format!("[Sniffer] Started capture on {}", self.sniffer_interface));
                            }
                            
                            if ui.button("🗑 Clear").clicked() {
                                self.sniffer_packets.clear();
                            }
                        }
                    });
                    
                    ui.separator();
                    ui.heading(format!("Captured Packets ({})", self.sniffer_packets.len()));
                    
                    egui::ScrollArea::vertical().max_height(450.0).show(ui, |ui| {
                        TableBuilder::new(ui)
                            .column(Column::initial(100.0).resizable(true))
                            .column(Column::initial(130.0).resizable(true))
                            .column(Column::initial(130.0).resizable(true))
                            .column(Column::initial(80.0).resizable(true))
                            .column(Column::initial(60.0).resizable(true))
                            .column(Column::remainder())
                            .header(20.0, |mut header| {
                                header.col(|ui| { ui.strong("Time"); });
                                header.col(|ui| { ui.strong("Source"); });
                                header.col(|ui| { ui.strong("Destination"); });
                                header.col(|ui| { ui.strong("Protocol"); });
                                header.col(|ui| { ui.strong("Length"); });
                                header.col(|ui| { ui.strong("Info"); });
                            })
                            .body(|mut body| {
                                for pkt in self.sniffer_packets.iter().rev().take(500) {
                                    body.row(18.0, |mut row| {
                                        row.col(|ui| { ui.label(&pkt.timestamp); });
                                        row.col(|ui| { ui.label(&pkt.src_ip); });
                                        row.col(|ui| { ui.label(&pkt.dst_ip); });
                                        row.col(|ui| { ui.label(&pkt.protocol); });
                                        row.col(|ui| { ui.label(format!("{}", pkt.length)); });
                                        row.col(|ui| { ui.label(&pkt.info); });
                                    });
                                }
                            });
                    });
                },
                Tab::Crawler => {
                     ui.heading("🕷 Crawler & Scanner");
                     ui.label("Deep Active Scan: Recursively visits links on the target domain.");
                     
                     ui.horizontal(|ui| {
                         ui.label("Start URL:");
                         ui.text_edit_singleline(&mut self.crawl_target);
                     });

                     if self.crawl_active {
                         ui.horizontal(|ui| {
                             ui.spinner();
                             ui.label(egui::RichText::new("Scanning Active...").color(egui::Color32::GREEN));
                         });
                         ui.label(format!("Now: {}", self.crawl_current_url));
                         if ui.button("⏹ Stop Scan").clicked() { 
                             self.crawl_active = false; 
                             self.show_report = true;
                         }
                     } else {
                         if ui.button("▶ Start Deep Scan").clicked() {
                             self.crawl_active = true;
                             self.crawl_queue.clear();
                             self.crawl_discovered.clear();
                             self.crawl_results.clear();
                             self.crawl_vulnerabilities.clear();
                             self.crawl_queue.push_back(self.crawl_target.clone());
                             self.logs.push(format!("[Crawler] Starting scan on {}", self.crawl_target));
                             self.crawl_idle_timer = 0.0;
                             self.show_report = false;
                         }
                         if !self.crawl_results.is_empty() && ui.button("📄 Show Last Report").clicked() {
                             self.show_report = true;
                         }
                     }

                     ui.separator();
                     ui.label(format!("Queue: {} | Discovered: {}", self.crawl_queue.len(), self.crawl_results.len()));
                     
                     egui::ScrollArea::vertical().show(ui, |ui| {
                         egui::Grid::new("crawl_grid").striped(true).show(ui, |ui| {
                            ui.label("URL"); ui.end_row();
                            for url in &self.crawl_results {
                                ui.label(url);
                                if self.crawl_vulnerabilities.contains(url) { 
                                    ui.colored_label(egui::Color32::RED, " [Risk]"); 
                                }
                                ui.end_row();
                            }
                         });
                     });
                }
                Tab::Decoder => {
                    ui.heading("🪄 Decoder / Encoder");
                    ui.label("Quickly transform data between formats.");
                    
                    ui.columns(2, |columns| {
                        columns[0].label("Input:");
                        columns[0].add(egui::TextEdit::multiline(&mut self.decoder_input).desired_width(f32::INFINITY).desired_rows(10));
                        
                        columns[1].label("Output:");
                        columns[1].add(egui::TextEdit::multiline(&mut self.decoder_output).desired_width(f32::INFINITY).desired_rows(10));
                    });

                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        // Base64
                        if ui.button("Base64 Encode").clicked() {
                            self.decoder_output = BASE64_STANDARD.encode(&self.decoder_input);
                        }
                        if ui.button("Base64 Decode").clicked() {
                            match BASE64_STANDARD.decode(&self.decoder_input.trim()) {
                                Ok(bytes) => self.decoder_output = String::from_utf8_lossy(&bytes).to_string(),
                                Err(e) => self.decoder_output = format!("Error: {}", e),
                            }
                        }
                        ui.separator();
                        // URL
                        if ui.button("URL Encode").clicked() {
                             // Using percent-encoding crate
                             use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
                             self.decoder_output = utf8_percent_encode(&self.decoder_input, NON_ALPHANUMERIC).to_string();
                        }
                        if ui.button("URL Decode").clicked() {
                            // Using percent-encoding crate
                            use percent_encoding::percent_decode_str;
                            if let Ok(s) = percent_decode_str(&self.decoder_input).decode_utf8() {
                                self.decoder_output = s.to_string();
                            } else {
                                self.decoder_output = "Error decoding UTF-8".into();
                            }
                        }
                        ui.separator();
                        // JWT Decoder
                        if ui.button("🔑 JWT Decode").clicked() {
                            let parts: Vec<&str> = self.decoder_input.trim().split('.').collect();
                            if parts.len() == 3 {
                                let mut result = String::new();
                                
                                // Decode Header
                                result.push_str("=== HEADER ===\n");
                                match BASE64_STANDARD.decode(parts[0]) {
                                    Ok(bytes) => {
                                        let header = String::from_utf8_lossy(&bytes);
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&header) {
                                            result.push_str(&serde_json::to_string_pretty(&json).unwrap_or(header.to_string()));
                                        } else {
                                            result.push_str(&header);
                                        }
                                    },
                                    Err(_) => {
                                        // Try URL-safe base64
                                        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                                        use base64::Engine;
                                        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(parts[0]) {
                                            let header = String::from_utf8_lossy(&bytes);
                                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&header) {
                                                result.push_str(&serde_json::to_string_pretty(&json).unwrap_or(header.to_string()));
                                            } else {
                                                result.push_str(&header);
                                            }
                                        } else {
                                            result.push_str("Failed to decode header");
                                        }
                                    }
                                }
                                
                                // Decode Payload
                                result.push_str("\n\n=== PAYLOAD ===\n");
                                match BASE64_STANDARD.decode(parts[1]) {
                                    Ok(bytes) => {
                                        let payload = String::from_utf8_lossy(&bytes);
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload) {
                                            result.push_str(&serde_json::to_string_pretty(&json).unwrap_or(payload.to_string()));
                                        } else {
                                            result.push_str(&payload);
                                        }
                                    },
                                    Err(_) => {
                                        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                                        use base64::Engine;
                                        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(parts[1]) {
                                            let payload = String::from_utf8_lossy(&bytes);
                                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload) {
                                                result.push_str(&serde_json::to_string_pretty(&json).unwrap_or(payload.to_string()));
                                            } else {
                                                result.push_str(&payload);
                                            }
                                        } else {
                                            result.push_str("Failed to decode payload");
                                        }
                                    }
                                }
                                
                                // Signature (just show raw)
                                result.push_str("\n\n=== SIGNATURE ===\n");
                                result.push_str(parts[2]);
                                
                                self.decoder_output = result;
                            } else {
                                self.decoder_output = "Invalid JWT format! Expected: header.payload.signature".into();
                            }
                        }
                    });
                }
            }
            // Logs moved to BottomPanel
            // ui.separator();
            // ui.collapsing("Logs", |ui| { for log in &self.logs { ui.label(log); } });

            // REPORT MODAL
            if self.show_report {
                egui::Window::new("📊 Scan Report")
                    .collapsible(false)
                    .resizable(true)
                    .show(ctx, |ui| {
                        ui.heading("VantaStalker Security Report");
                        ui.separator();
                        ui.label(format!("Target: {}", self.crawl_target));
                        ui.label(format!("Total URLs Scanned: {}", self.crawl_discovered.len()));
                        ui.label(format!("Potential Risks Found: {}", self.crawl_vulnerabilities.len()));
                        ui.separator();
                        
                        if self.crawl_vulnerabilities.is_empty() {
                            ui.label("No obvious high-risk endpoints found (publicly linked).");
                        } else {
                            ui.label(egui::RichText::new("⚠️ Potential Vulnerabilities Found:").color(egui::Color32::RED).strong());
                            egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                for v in &self.crawl_vulnerabilities {
                                    ui.horizontal(|ui| {
                                        ui.label("🔴");
                                        ui.label(v);
                                    });
                                }
                            });
                        }
                        
                        ui.separator();
                        ui.label("This report lists endpoints matching known sensitive patterns (admin, api, config, etc.). Manual verification required.");
                        
                        if ui.button("Close").clicked() {
                            self.show_report = false;
                        }
                    });
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 900.0]), 
        ..Default::default()
    };
    eframe::run_native("VantaStalker Pro", options, Box::new(|cc| Ok(Box::new(VantaApp::new(cc)))))
}
