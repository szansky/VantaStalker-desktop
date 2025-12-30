use scraper::{Html, Selector};
use reqwest::Client;
use crate::core::models::AuthProfile;

pub async fn probe_login_form(url: &str, user: &str, pass: &str) -> Option<AuthProfile> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build().ok()?;

    // 1. GET key parts
    let resp = client.get(url).send().await.ok()?;
    let html_body = resp.text().await.ok()?;
    
    // 2. Parse (Sync)
    let candidate = parse_login_form(&html_body, url);

    // 3. Attempt Login (ASYNC PART)
    if let Some((action, method, user_field, pass_field)) = candidate {
         // Construct Login Body
         let login_body = format!("{}={}&{}={}", user_field, user, pass_field, pass);
         
         let mut probe_profile = AuthProfile::default();
         probe_profile.enabled = true;
         probe_profile.trigger_status_codes = vec![401];
         probe_profile.login_url = action.clone();
         probe_profile.login_method = method.clone();
         probe_profile.login_body = login_body;
         probe_profile.login_headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
         
         if let Ok(login_resp) = client.post(&action)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(probe_profile.login_body.clone())
            .send().await 
         {
             if let Ok(resp_body) = login_resp.text().await {
                 if resp_body.contains("token") {
                     if resp_body.contains("\"token\"") {
                         probe_profile.token_extraction_regex = "\"token\"\\s*:\\s*\"(.*?)\"".into();
                     } else if resp_body.contains("\"access_token\"") {
                         probe_profile.token_extraction_regex = "\"access_token\"\\s*:\\s*\"(.*?)\"".into();
                     }
                     
                     probe_profile.token_dest_header = "Authorization".into();
                     probe_profile.token_format = "Bearer {}".into();
                     
                     return Some(probe_profile);
                 }
             }
         }
    }
    
    None
}

fn parse_login_form(html: &str, base_url: &str) -> Option<(String, String, String, String)> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input").unwrap();

    for form in document.select(&form_selector) {
        let mut user_field = String::new();
        let mut pass_field = String::new();
        let mut action = base_url.to_string(); 
        let mut method = "GET".to_string(); 

        if let Some(act) = form.value().attr("action") {
            if act.starts_with("http") {
                action = act.to_string();
            } else {
                 if act.starts_with("/") {
                     if let (Some(slash_idx), _) = (base_url.find("://"), 0) {
                         let proto_end = base_url[slash_idx + 3..].find('/').map(|i| i + slash_idx + 3).unwrap_or(base_url.len());
                         let domain = &base_url[..proto_end];
                         action = format!("{}{}", domain, act);
                     }
                 } else {
                     action = format!("{}/{}", base_url, act); 
                 }
            }
        }
        
        if let Some(m) = form.value().attr("method") {
            method = m.to_uppercase();
        }

        for input in form.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("");
            let type_ = input.value().attr("type").unwrap_or("text");

            if name.contains("user") || name.contains("login") || name.contains("email") || type_ == "email" {
                user_field = name.to_string();
            }
            if name.contains("pass") || type_ == "password" {
                pass_field = name.to_string();
            }
        }

        if !user_field.is_empty() && !pass_field.is_empty() {
             return Some((action, method, user_field, pass_field));
        }
    }
    None
}
