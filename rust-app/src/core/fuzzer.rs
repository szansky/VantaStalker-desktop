use reqwest::Client;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct FuzzerResult {
    pub url: String,
    pub status: u16,
    pub length: u64,
}

pub async fn run_fuzzer(
    target_url: String,
    wordlist: Vec<String>,
    threads: usize,
    tx: mpsc::Sender<FuzzerResult>,
) {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();
    
    let client = Arc::new(client);
    let target_base = if target_url.ends_with('/') {
        target_url.trim_end_matches('/').to_string()
    } else {
        target_url
    };

    // Simple chunking for parallelism (or just semaphore)
    // For simplicity with Tokio, we can use a semaphore to limit concurrency
    let semaphore = Arc::new(tokio::sync::Semaphore::new(threads));
    
    for word in wordlist {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let tx = tx.clone();
        let url = format!("{}/{}", target_base, word);
        
        tokio::spawn(async move {
            if let Ok(res) = client.get(&url).send().await {
                let status = res.status().as_u16();
                // Filter interesting statuses
                if status != 404 {
                    let length = res.content_length().unwrap_or(0);
                    let _ = tx.send(FuzzerResult { url, status, length }).await;
                }
            }
            drop(permit);
        });
    }
}
