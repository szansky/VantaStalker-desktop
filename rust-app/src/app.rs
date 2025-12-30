use eframe::egui::{self, Visuals, Color32};
use std::collections::{HashSet, VecDeque, HashMap};
use std::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::mpsc as tokio_mpsc;
use std::thread;
use std::sync::Arc;
use tokio::runtime::Runtime;
use std::process::{Command, Stdio};
use std::io::{self, BufRead, Write};
use rusqlite::Connection;
use crate::core::models::*;
use hickory_resolver::Resolver as HickoryResolver;
use std::net::IpAddr;

#[allow(dead_code)]
pub struct VantaApp {
    // UI State
    pub target_url: String,
    pub logs: Vec<String>,
    pub intercept_enabled: bool,
    pub intercept_responses: bool, 
    pub active_tab: Tab,
    
    // Data State
    pub queue: VecDeque<InterceptItem>, 
    pub history: Vec<HistoryItem>,
    
    // Scope State
    pub scope_domains: Vec<String>,
    pub new_scope_domain: String,

    // Intercept Editor
    pub edit_method: String,
    pub edit_url: String, 
    pub edit_status: String, 
    pub edit_body: String,
    pub edit_headers: Vec<(String, String)>,

    // Repeater State
    pub rep_url: String,
    pub rep_method: String,
    pub rep_headers: Vec<(String, String)>,
    pub rep_body: String,
    pub rep_response: String,

    // Intruder State
    pub intr_url: String,
    pub intr_method: String,
    pub intr_headers: std::collections::BTreeMap<String, String>,
    pub intr_body_template: String, 
    pub intr_payloads: String, // Set 1
    pub intr_payloads_2: String, // Set 2 (New)
    pub intr_attack_mode: crate::core::models::AttackMode, // New
    pub intr_results: Vec<IntruderResult>,
    pub intr_running: bool,
    pub intr_current_idx: usize,
    pub intr_mode: IntruderMode,
    pub intr_transform: PayloadTransform,
    
    // Crawler State
    pub crawl_discovered: HashSet<String>,
    pub crawl_results: Vec<String>,
    pub crawl_vulnerabilities: Vec<String>, // "Report" items
    pub crawl_active: bool,
    pub crawl_target: String,
    pub crawl_current_url: String, // "Now scanning..."
    pub crawl_queue: VecDeque<String>,
    pub _crawl_max_depth: u32,
    pub _crawl_current_depth: u32,
    pub crawl_timer: f32,
    pub crawl_idle_timer: f32, // Auto-stop detection
    pub show_report: bool, // Modal state

    // Active Scanner State (Legacy)
    pub scanner_active: bool,
    pub scanner_queue: VecDeque<String>, 
    pub scanner_findings: Vec<ScannerFinding>,

    pub pending_scans: HashMap<u32, (String, String)>, // ID -> (Url, Payload)
    pub scan_id_counter: u32,

    // IPC Channels
    pub tx_command: Sender<NodeCommand>,
    pub rx_event: Receiver<NodeEvent>,

    // Recon State
    pub recon_domain: String,
    pub recon_wordlist: String,
    pub recon_results: Vec<(String, String)>,
    pub recon_running: bool,
    
    // Directory Fuzzer
    pub fuzzer_running: bool,
    pub fuzzer_url: String,
    pub fuzzer_wordlist: String,
    pub fuzzer_results: Vec<crate::core::fuzzer::FuzzerResult>,
    pub tx_fuzzer: Option<tokio::sync::mpsc::Sender<(String, Vec<String>)>>,
    pub rx_fuzzer: tokio::sync::mpsc::Receiver<crate::core::fuzzer::FuzzerResult>,

    // SSL Analyzer
    pub ssl_target: String,
    pub ssl_result: crate::core::ssl::SslInfo,

    // Async Intruder Channel

    // Async Intruder Channel
    pub tx_intruder_job: tokio_mpsc::UnboundedSender<AsyncIntruderJob>,
    pub rx_intruder_result: Receiver<AsyncIntruderResult>,
    
    // Async Recon Channel
    pub tx_recon_job: tokio_mpsc::UnboundedSender<AsyncReconJob>,
    pub rx_recon_result: Receiver<AsyncReconResult>,

    // Port Scanner State
    pub portscan_target: String,
    pub portscan_port_range: String,
    pub portscan_results: Vec<(u16, String)>,
    pub portscan_running: bool,
    
    // Async Port Scanner Channel
    pub tx_portscan_job: tokio_mpsc::UnboundedSender<AsyncPortScanJob>,
    pub rx_portscan_result: Receiver<AsyncPortScanResult>,

    // Active Scanner State
    pub activescan_target_url: String,
    pub activescan_findings: Vec<ActiveScanFinding>,
    pub activescan_running: bool,
    pub activescan_tested: usize,
    
    // Async Active Scanner Channel
    pub tx_activescan_job: tokio_mpsc::UnboundedSender<AsyncActiveScanJob>,
    pub rx_activescan_result: Receiver<AsyncActiveScanResult>,

    // Sniffer State
    pub sniffer_packets: Vec<CapturedPacket>,
    pub sniffer_running: bool,
    pub sniffer_interface: String,
    pub rx_sniffer: Receiver<CapturedPacket>,
    pub sniffer_stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,

    pub editor_loaded_id: Option<u32>, 
    pub editor_is_response: bool,

    // Decoder State
    pub decoder_input: String,
    pub decoder_output: String,

    // UI View State
    pub view_split_horizontal: bool,
    // Configuration
    pub config: crate::core::config::AppConfig,
    
    // Collaborator
    pub collab_port: String,
    pub collab_running: bool,
    pub collab_interactions: Vec<crate::core::models::OASTInteraction>,
    pub tx_collab: tokio::sync::mpsc::UnboundedSender<crate::core::models::OASTInteraction>,

    pub rx_collab: tokio::sync::mpsc::UnboundedReceiver<crate::core::models::OASTInteraction>,

    // WebSockets
    pub ws_url: String,
    pub ws_connected: bool,
    pub ws_input: String,
    pub ws_history: Vec<crate::core::models::WSHistoryItem>,
    pub tx_ws_in: tokio::sync::mpsc::UnboundedSender<crate::core::models::WSHistoryItem>, // Recv from socket -> UI
    pub rx_ws_in: tokio::sync::mpsc::UnboundedReceiver<crate::core::models::WSHistoryItem>,
    pub tx_ws_out: Option<tokio::sync::mpsc::UnboundedSender<crate::core::models::WSMessage>>, // UI -> Socket

    // Site Map
    pub sitemap_root: crate::core::sitemap::SiteMapNode,
    pub show_sitemap: bool,

    // Diffing
    pub diff_input_a: String,
    pub diff_input_b: String,
    pub diff_result: Vec<crate::core::diffing::DiffLine>,

    // Scripting
    pub script_engine: crate::core::scripting::ScriptEngine,
    pub script_code: String,
    pub script_enabled: bool,
    pub script_compiled: bool,
    pub script_error: Option<String>,

    // JWT
    pub jwt_input: String,
    pub jwt_parsed: crate::core::jwt::JwtToken,

    // Layout / Theme
    pub is_dark_mode: bool,
    pub conn: Connection,

    // Needed for progress tracking if we use it
    pub jobs_active: usize,
    // Auth Helper State
    pub auth_profile: AuthProfile,
    // Async Channels
    pub tx_auth_probe: std::sync::mpsc::Sender<AuthProfile>,
    pub rx_auth_probe: std::sync::mpsc::Receiver<AuthProfile>,
}

impl VantaApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx_command, rx_cmd_thread) = mpsc::channel::<NodeCommand>();
        let (tx_event, rx_event) = mpsc::channel::<NodeEvent>();
        // let (tx_job, rx_job) = tokio::sync::mpsc::channel::<AsyncActiveScanJob>(100); // Removed unused duplicate
        // let (tx_recon, rx_recon) = tokio::sync::mpsc::channel::<AsyncReconJob>(100); // Removed unused duplicate
        let (tx_auth_probe, rx_auth_probe) = std::sync::mpsc::channel(); // Standard mpsc for UI thread

        let config = crate::core::config::AppConfig::load(); // Load Config
        let _ua = config.user_agent.clone();
        
        // Native Async Intruder Channels (Tokio)
        let (tx_intruder_job, mut rx_job_thread) = tokio_mpsc::unbounded_channel::<AsyncIntruderJob>();
        let (tx_intruder_result, rx_intruder_result) = mpsc::channel::<AsyncIntruderResult>();
        let tx_intruder_res_clone = tx_intruder_result.clone();

        // Native Async Recon Channels (Tokio)
        let (tx_recon_job, mut rx_recon_thread) = tokio_mpsc::unbounded_channel::<AsyncReconJob>();
        let (tx_recon_res, rx_recon_result) = mpsc::channel::<AsyncReconResult>();
        let tx_recon_res_clone = tx_recon_res.clone();

        // Native Async Port Scan
        let (tx_portscan_job, mut rx_portscan_thread) = tokio_mpsc::unbounded_channel::<AsyncPortScanJob>();
        let (tx_portscan_result, rx_portscan_result) = mpsc::channel::<AsyncPortScanResult>();
        let tx_portscan_res_clone = tx_portscan_result.clone();

        // Native Async Active Scan
        let (tx_activescan_job, mut rx_activescan_thread) = tokio_mpsc::unbounded_channel::<AsyncActiveScanJob>();
        let (tx_activescan_result, rx_activescan_result) = mpsc::channel::<AsyncActiveScanResult>();
        let tx_activescan_res_clone = tx_activescan_result.clone();

        // Collaborator (Tokio Channel)
        let (tx_collab, rx_collab) = tokio_mpsc::unbounded_channel::<crate::core::models::OASTInteraction>();
        
        // WebSockets (Tokio Channel)
        let (tx_ws_in, rx_ws_in) = tokio_mpsc::unbounded_channel::<crate::core::models::WSHistoryItem>();

        // Fuzzer (Tokio Channel)
        let (tx_fuzzer_cmd, mut rx_fuzzer_cmd) = tokio::sync::mpsc::channel::<(String, Vec<String>)>(10);
        let (tx_fuzzer_res, rx_fuzzer_res) = tokio::sync::mpsc::channel::<crate::core::fuzzer::FuzzerResult>(100);
        let tx_res_clone = tx_fuzzer_res.clone();

        // Spawn Tokio Runtime Thread
         thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async move {
                // Spawn Fuzzer Worker (inside runtime context)
                tokio::spawn(async move {
                    while let Some((url, wordlist)) = rx_fuzzer_cmd.recv().await {
                         crate::core::fuzzer::run_fuzzer(url, wordlist, 10, tx_res_clone.clone()).await;
                    }
                });
                
                // We use select! to handle both job queues concurrently
                loop {
                    tokio::select! {
                        Some(job) = rx_job_thread.recv() => {
                             let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .redirect(reqwest::redirect::Policy::none())
                                .build()
                                .unwrap();
        
                             let payload_sets = job.payload_sets;
                             let mode = job.attack_mode;
                             let template = Arc::new(job.body_template);
                             let url = Arc::new(job.url);
                             let method = Arc::new(job.method);
                             let headers = Arc::new(job.headers);
                             
                             let tx = tx_intruder_res_clone.clone();

                             // Strategy Selection
                             match mode {
                                 crate::core::models::AttackMode::Sniper => {
                                     // Sniper: 1 set, iterate
                                     if let Some(payloads) = payload_sets.first() {
                                         for (idx, payload) in payloads.iter().enumerate() {
                                             let p = payload.clone();
                                             let client = client.clone();
                                             let tx = tx.clone();
                                             let tmpl = template.clone();
                                             let u = url.clone();
                                             let m = method.clone();
                                             let h = headers.clone();
                                             
                                             tokio::spawn(async move {
                                                 let body = tmpl.replace("§payload§", &p); // Replace all for Sniper usually, or positional? Burp Sniper replaces *one* position at a time (iterating over positions). 
                                                 // MVP Sniper: Just replace all "§payload§" with current payload. Pro behavior (iterating positions) is complex.
                                                 
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
                                     }
                                 },
                                 crate::core::models::AttackMode::ClusterBomb => {
                                    // ClusterBomb: Cartesian Product (Max 2 sets for this MVP block)
                                    if payload_sets.len() >= 2 {
                                        let set1 = &payload_sets[0];
                                        let set2 = &payload_sets[1];
                                        let mut global_idx = 0;
            
                                        for p1 in set1 {
                                            for p2 in set2 {
                                                 let p1_c = p1.clone();
                                                 let p2_c = p2.clone();
                                                 let client = client.clone();
                                                 let tx = tx.clone();
                                                 let tmpl = template.clone();
                                                 let u = url.clone();
                                                 let m = method.clone();
                                                 let h = headers.clone();
                                                 let idx = global_idx;
                                                 global_idx += 1;
            
                                                 tokio::spawn(async move {
                                                     // Positional Replacement: First marker gets p1, second gets p2
                                                     let body = tmpl.replacen("§payload§", &p1_c, 1).replacen("§payload§", &p2_c, 1);
                                                     let combined_payload = format!("{}, {}", p1_c, p2_c);
            
                                                     let mut req_builder = match m.as_str() {
                                                         "POST" => client.post(u.as_str()),
                                                         _ => client.get(u.as_str()),
                                                     };
                                                     for (k, v) in h.iter() { req_builder = req_builder.header(k, v); }
                                                     if !body.is_empty() { req_builder = req_builder.body(body); }
                        
                                                     match req_builder.send().await {
                                                         Ok(resp) => {
                                                             let status = resp.status().as_u16();
                                                             let len = resp.content_length().unwrap_or(0) as usize; 
                                                             let _ = tx.send(AsyncIntruderResult::Progress { idx, payload: combined_payload, status, length: len });
                                                         },
                                                         Err(_) => { }
                                                     }
                                                 });
                                            }
                                        }
                                    }
                                 },
                                 crate::core::models::AttackMode::Pitchfork => {
                                     // Pitchfork: Zip (Max 2 sets for MVP)
                                     if payload_sets.len() >= 2 {
                                         let set1 = &payload_sets[0];
                                         let set2 = &payload_sets[1];
                                         
                                         for (idx, (p1, p2)) in set1.iter().zip(set2.iter()).enumerate() {
                                             let p1_c = p1.clone();
                                             let p2_c = p2.clone();
                                             let client = client.clone();
                                             let tx = tx.clone();
                                             let tmpl = template.clone();
                                             let u = url.clone();
                                             let m = method.clone();
                                             let h = headers.clone();
            
                                             tokio::spawn(async move {
                                                 let body = tmpl.replacen("§payload§", &p1_c, 1).replacen("§payload§", &p2_c, 1);
                                                 let combined_payload = format!("{}, {}", p1_c, p2_c);
            
                                                 let mut req_builder = match m.as_str() {
                                                     "POST" => client.post(u.as_str()),
                                                     _ => client.get(u.as_str()),
                                                 };
                                                 for (k, v) in h.iter() { req_builder = req_builder.header(k, v); }
                                                 if !body.is_empty() { req_builder = req_builder.body(body); }
                    
                                                 match req_builder.send().await {
                                                     Ok(resp) => {
                                                         let status = resp.status().as_u16();
                                                         let len = resp.content_length().unwrap_or(0) as usize; 
                                                         let _ = tx.send(AsyncIntruderResult::Progress { idx, payload: combined_payload, status, length: len });
                                                     },
                                                     Err(_) => { }
                                                 }
                                             });
                                         }
                                     }
                                 }
                             }
                        },
                        Some(job) = rx_recon_thread.recv() => {
                            // hickory-resolver builder
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
                                    if let Ok(Ok(_)) = timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await {
                                        let service = match port {
                                            21 => "FTP", 22 => "SSH", 80 => "HTTP", 443 => "HTTPS", _ => "Unknown"
                                        };
                                        let _ = tx.send(AsyncPortScanResult::Open { port, service: service.into() });
                                    }
                                });
                            }
                        },
                         Some(job) = rx_activescan_thread.recv() => {
                            let tx = tx_activescan_res_clone.clone();
                            let url_base = job.url;
                            let param = job.param;
                            
                             let client = reqwest::Client::builder()
                                .danger_accept_invalid_certs(true)
                                .timeout(std::time::Duration::from_secs(5))
                                .build()
                                .unwrap();
                            
                            // Simplified payloads for brevity in this file
                            let payloads = vec![
                                ("'<script>alert(1)</script>", "XSS"),
                                ("' OR 1=1--", "SQL Injection"),
                            ];

                            for (pl, vuln) in payloads {
                                 let tx = tx.clone();
                                 let client = client.clone();
                                 let u = url_base.clone();
                                 let p = param.clone();
                                 let payload = pl.to_string();
                                 let v_type = vuln.to_string();

                                 tokio::spawn(async move {
                                      let test_url = format!("{}?{}={}", u, p, urlencoding::encode(&payload));
                                      if let Ok(resp) = client.get(&test_url).send().await {
                                          if let Ok(body) = resp.text().await {
                                              if (v_type == "XSS" && body.contains(&payload)) || 
                                                 (v_type == "SQL Injection" && body.to_lowercase().contains("sql")) {
                                                     let _ = tx.send(AsyncActiveScanResult::Finding(ActiveScanFinding {
                                                         url: test_url,
                                                         param: p,
                                                         vuln_type: v_type,
                                                         payload,
                                                         evidence: "Found".into(),
                                                         severity: "High".into()
                                                     }));
                                                 }
                                          }
                                      }
                                 });
                            }
                        }
                        else => { break; }
                    }
                }
            });
         });

        // Spawn Node.js
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

        // Sniffer Channel
        let (_, rx_sniffer) = mpsc::channel::<CapturedPacket>(); // Placeholder, real one in main? Or implement sniffer logic here?
        // To properly implement sniffer here we need pnet dep. For now we just init empty.
        // We will fix packet capture later.

        Self {
            target_url: "http://example.com".to_owned(),
            logs: vec!["Refreshed GUI. Ready to launch.".to_owned()],
            intercept_enabled: true,
            intercept_responses: false,
            active_tab: Tab::Dashboard,
            queue: VecDeque::new(),
            history: Vec::new(),
            scope_domains: Vec::new(),
            conn,
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
            intr_url: "http://example.com/login".into(),
            intr_method: "POST".into(),
            intr_headers: std::collections::BTreeMap::from([("Content-Type".into(), "application/json".into())]),
            intr_body_template: "{\"username\": \"admin\", \"password\": \"§payload§\"}".into(),
            intr_payloads: "123456\npassword\n".into(),
            intr_payloads_2: "".into(),
            intr_attack_mode: crate::core::models::AttackMode::Sniper,
            intr_results: Vec::new(),
            intr_running: false,
            intr_current_idx: 0,
            intr_mode: IntruderMode::Native,
            intr_transform: PayloadTransform::Identity,
            crawl_discovered: HashSet::new(),
            crawl_results: Vec::new(),
            crawl_vulnerabilities: Vec::new(),
            crawl_active: false,
            crawl_target: "http://example.com".into(),
            crawl_current_url: "Idle".into(),
            view_split_horizontal: false,
            crawl_queue: VecDeque::new(),
            _crawl_max_depth: 2,
            _crawl_current_depth: 0,
            crawl_timer: 0.0,
            crawl_idle_timer: 0.0,
            show_report: false,
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
            recon_domain: "example.com".into(),
            recon_wordlist: "www\nmail\n".into(),
            recon_results: Vec::new(),

            fuzzer_running: false,
            fuzzer_url: String::new(),
            fuzzer_wordlist: "admin\nbackup\n.git\n.env\napi\nlogin\n".to_string(),
            fuzzer_results: Vec::new(),
            tx_fuzzer: Some(tx_fuzzer_cmd),
            rx_fuzzer: rx_fuzzer_res,

            ssl_target: String::new(),
            ssl_result: crate::core::ssl::SslInfo::default(),

            recon_running: false,
            portscan_target: "127.0.0.1".into(),
            portscan_port_range: "1-1000".into(),
            portscan_results: Vec::new(),
            portscan_running: false,
            tx_portscan_job,
            rx_portscan_result,
            activescan_target_url: "http://example.com/search?q=test".into(),
            activescan_findings: Vec::new(),
            activescan_running: false,
            activescan_tested: 0,
            tx_activescan_job,
            rx_activescan_result,
            sniffer_packets: Vec::new(),
            sniffer_running: false,
            sniffer_interface: "eth0".into(),
            rx_sniffer,
            sniffer_stop_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            editor_loaded_id: None, 
            editor_is_response: false,
            decoder_input: String::new(),
            decoder_output: String::new(),
            is_dark_mode: true,
            jobs_active: 0,
            auth_profile: AuthProfile::default(),
            tx_auth_probe,
            rx_auth_probe,
            config: crate::core::config::AppConfig::load(),
            
            collab_port: "3000".into(),
            collab_running: false,
            collab_interactions: Vec::new(),
            tx_collab,
            rx_collab,

            ws_url: "wss://echo.websocket.org".into(),
            ws_connected: false,
            ws_input: "".into(),
            ws_history: Vec::new(),
            tx_ws_in,
            rx_ws_in,
            tx_ws_out: None,

            sitemap_root: crate::core::sitemap::SiteMapNode::default(),
            show_sitemap: true,

            diff_input_a: String::new(),
            diff_input_b: String::new(),
            diff_result: Vec::new(),

            script_engine: crate::core::scripting::ScriptEngine::default(),
            script_code: r#"
fn on_request(req) {
    // print("Checking: " + req.url);
    return req; 
}
"#.trim().to_string(),
            script_enabled: false,
            script_compiled: false,
            script_error: None,

            jwt_input: String::new(),
            jwt_parsed: crate::core::jwt::JwtToken::default(),
        }
    }

    pub fn apply_theme(&self, ctx: &egui::Context, dark: bool) {
         let mut visuals = if dark { Visuals::dark() } else { Visuals::light() };
         if dark {
             visuals.window_rounding = egui::Rounding::same(8.0);
             visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(20, 20, 25); 
         }
         ctx.set_visuals(visuals);
    }
    
    pub fn start_sniffer(&mut self) {
        // This is where pnet logic would go in app.rs
        // For now, logging stub.
        self.logs.push("Sniffer started (Stub)".into());
        self.sniffer_running = true;
    }
}

impl eframe::App for VantaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll Collaborator
        while let Ok(interaction) = self.rx_collab.try_recv() {
            self.collab_interactions.push(interaction);
            ctx.request_repaint();
        }

        // Poll WebSockets
        while let Ok(msg) = self.rx_ws_in.try_recv() {
            self.ws_history.push(msg);
            ctx.request_repaint();
        }

        // Poll Tokio Channels (Others)
        while let Ok(interaction) = self.rx_collab.try_recv() {
            self.collab_interactions.push(interaction);
            ctx.request_repaint(); // Ensure UI updates immediately
        }

        // Poll Fuzzer
        while let Ok(res) = self.rx_fuzzer.try_recv() {
            self.fuzzer_results.push(res);
        }
        
        // Poll Main Node Events (Proxy/CDP)
        while let Ok(event) = self.rx_event.try_recv() {
            match event {
                NodeEvent::RequestIntercepted { id, method, url, headers, body } => {
                    // 1. Populate Site Map
                    crate::core::sitemap::insert_url(&mut self.sitemap_root, &url);

                    // 2. Add to History
                    // Check if exists to avoid dupes? (IDs are unique usually)
                    self.history.push(crate::core::models::HistoryItem {
                        id,
                        method: method.clone(),
                        url: url.clone(),
                        status: "PENDING".into(),
                    });
                    
                    // 3. Scripting Engine (Auto-Modify)
                    if self.script_enabled && self.script_compiled {
                        // Attempt to run script
                        match self.script_engine.on_request(&method, &url, &headers.to_string(), body.as_deref().unwrap_or("")) {
                            Ok(Some((new_method, _new_url, new_headers, new_body))) => {
                                self.logs.push(format!("🧩 Script modified request: {}", url));
                                // Send Continue with modifications
                                // We need to parse headers back to Value
                                let new_headers_val: serde_json::Value = serde_json::from_str(&new_headers).unwrap_or(headers.clone());
                                
                                let _ = self.tx_command.send(crate::core::models::NodeCommand::CONTINUE {
                                    id,
                                    method: new_method,
                                    headers: new_headers_val,
                                    body: Some(new_body),
                                    intercept_response: true, // Keep intercepting response for passive scan?
                                });
                            },
                            Ok(None) => {}, // No modification
                            Err(e) => {
                                self.logs.push(format!("Script Execution Error: {}", e));
                            }
                        }
                    }

                    // 4. Interceptor Logic (Stub)
                },
                NodeEvent::ResponseIntercepted { id, status, headers, body } => {
                    // Update History
                    if let Some(item) = self.history.iter_mut().find(|i| i.id == id) {
                        item.status = status.to_string();
                        
                        // Passive Scan (Response)
                        let findings = crate::core::passive::scan_transaction(&item.url, &headers.to_string(), &body);
                        for f in findings {
                             // Dedup: Check if we already have this vuln for this URL/Param
                             if !self.activescan_findings.iter().any(|existing| existing.url == f.url && existing.vuln_type == f.vuln_type && existing.evidence == f.evidence) {
                                  self.activescan_findings.push(f);
                             }
                        }
                    }
                },
                NodeEvent::LOG { message } => {
                    self.logs.push(format!("[Node] {}", message));
                    // If crawler logs URLs, we could parse them too.
                },
                _ => {}
            }
            ctx.request_repaint();
        }
        
        // Render UI
        use crate::ui::*;

        self.apply_theme(ctx, self.is_dark_mode);

        // Handle Auth Auto-Detect Results
        if let Ok(profile) = self.rx_auth_probe.try_recv() {
             self.logs.push(format!("✅ Auth Auto-Configured! Token Regex: {}", profile.token_extraction_regex));
             // Preserve user inputs
             let user_input_user = self.auth_profile.target_username.clone();
             let user_input_pass = self.auth_profile.target_password.clone();
             
             self.auth_profile = profile;
             self.auth_profile.target_username = user_input_user;
             self.auth_profile.target_password = user_input_pass;
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
             egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("📂 Open Project...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("Vanta Project", &["vanta", "db"]).pick_file() {
                            let path_str = path.to_string_lossy().to_string();
                            match crate::core::db::load_project(self, &path_str) {
                                Ok(_) => self.logs.push(format!("Loaded project: {}", path_str)),
                                Err(e) => self.logs.push(format!("Error loading project: {}", e)),
                            }
                            ui.close_menu();
                        }
                    }
                    if ui.button("💾 Save Project As...").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("Vanta Project", &["vanta", "db"]).save_file() {
                             let path_str = path.to_string_lossy().to_string();
                             // Init DB if new file
                             let _ = crate::core::db::init_db(&path_str);
                             match crate::core::db::save_project(self, &path_str) {
                                Ok(_) => self.logs.push(format!("Saved project to: {}", path_str)),
                                Err(e) => self.logs.push(format!("Error saving project: {}", e)),
                             }
                             ui.close_menu();
                        }
                    }
                });
             });
        });

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button(if self.show_sitemap { "⬅" } else { "➡" }).clicked() {
                    self.show_sitemap = !self.show_sitemap;
                }
                ui.heading("🕸 VantaStalker v2.0");
                ui.selectable_value(&mut self.active_tab, Tab::Dashboard, "📊 Dashboard");
                ui.selectable_value(&mut self.active_tab, Tab::Intercept, "🔴 Intercept");
                ui.selectable_value(&mut self.active_tab, Tab::History, "📜 History");
                ui.selectable_value(&mut self.active_tab, Tab::Repeater, "🔁 Repeater");
                ui.selectable_value(&mut self.active_tab, Tab::Scope, "🎯 Scope");
                ui.selectable_value(&mut self.active_tab, Tab::Intruder, "💣 Intruder");
                ui.selectable_value(&mut self.active_tab, Tab::Recon, "📡 Recon");
                ui.selectable_value(&mut self.active_tab, Tab::PortScanner, "🔌 Ports");
                ui.selectable_value(&mut self.active_tab, Tab::ActiveScanner, "🤖 Scanner");
                ui.selectable_value(&mut self.active_tab, Tab::Sniffer, "🦈 Sniffer");
                ui.selectable_value(&mut self.active_tab, Tab::Crawler, "🕷 Crawler");
                ui.selectable_value(&mut self.active_tab, Tab::Collaborator, "📡 Collaborator");
                ui.selectable_value(&mut self.active_tab, Tab::WebSockets, "🔌 WebSockets");
                ui.selectable_value(&mut self.active_tab, Tab::Diff, "🧬 Diffing");
                ui.selectable_value(&mut self.active_tab, Tab::Scripting, "🧩 Scripting");
                ui.selectable_value(&mut self.active_tab, Tab::JWT, "🔐 JWT");
                ui.selectable_value(&mut self.active_tab, Tab::Decoder, "🪄 Decoder");
                ui.selectable_value(&mut self.active_tab, Tab::Auth, "🔐 Auth");
            });
        });

        if self.show_sitemap {
            egui::SidePanel::left("sitemap_panel").resizable(true).default_width(200.0).show(ctx, |ui| {
                crate::ui::sitemap::render_panel(self, ui);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                Tab::Dashboard => dashboard::render(self, ui),
                Tab::Intercept => interceptor::render(self, ui),
                Tab::History => history::render(self, ui),
                Tab::Repeater => repeater::render(self, ui),
                Tab::Scope => scope::render(self, ui),
                Tab::Intruder => intruder::render(self, ui),
                Tab::Recon => recon::render(self, ui),
                Tab::PortScanner => port_scanner::render(self, ui),
                Tab::ActiveScanner => active_scanner::render(self, ui),
                Tab::Sniffer => sniffer::render(self, ui),
                Tab::Crawler => crawler::render(self, ui),
                Tab::Collaborator => collaborator::render(self, ui),
                Tab::WebSockets => websockets::render(self, ui),
                Tab::Diff => diffing::render(self, ui),
                Tab::Scripting => scripting::render(self, ui),
                Tab::JWT => jwt::render(self, ui),
                Tab::Decoder => decoder::render(self, ui),
                Tab::Auth => auth::render(self, ui),
            }
        });
    }
}
