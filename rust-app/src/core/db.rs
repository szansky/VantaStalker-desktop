use rusqlite::{params, Connection, Result};
use crate::app::VantaApp;
use crate::core::models::{HistoryItem, ActiveScanFinding};

use serde_json;

pub fn init_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY,
            method TEXT,
            url TEXT,
            status TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS scope (
            domain TEXT PRIMARY KEY
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            url TEXT,
            param TEXT,
            vuln_type TEXT,
            payload TEXT,
            evidence TEXT,
            severity TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS sitemap (
            id INTEGER PRIMARY KEY,
            data TEXT
        )",
        [],
    )?;

    Ok(conn)
}

pub fn save_project(app: &VantaApp, path: &str) -> Result<()> {
    let mut conn = Connection::open(path)?;
    let tx = conn.transaction()?;

    // 1. Clear existing data (overwrite strategy for now)
    tx.execute("DELETE FROM history", [])?;
    tx.execute("DELETE FROM scope", [])?;
    tx.execute("DELETE FROM findings", [])?;
    tx.execute("DELETE FROM sitemap", [])?;

    // 2. Save History
    {
        let mut stmt = tx.prepare("INSERT INTO history (id, method, url, status) VALUES (?1, ?2, ?3, ?4)")?;
        for item in &app.history {
            stmt.execute(params![item.id, item.method, item.url, item.status])?;
        }
    }

    // 3. Save Scope
    {
        let mut stmt = tx.prepare("INSERT INTO scope (domain) VALUES (?1)")?;
        for domain in &app.scope_domains {
            stmt.execute(params![domain])?;
        }
    }

    // 4. Save Findings
    {
        let mut stmt = tx.prepare("INSERT INTO findings (url, param, vuln_type, payload, evidence, severity) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
        for finding in &app.activescan_findings {
            stmt.execute(params![finding.url, finding.param, finding.vuln_type, finding.payload, finding.evidence, finding.severity])?;
        }
    }

    // 5. Save Sitemap (JSON Blob for simplicity)
    if let Ok(json) = serde_json::to_string(&app.sitemap_root) {
        tx.execute("INSERT INTO sitemap (data) VALUES (?1)", params![json])?;
    }

    tx.commit()?;
    Ok(())
}

pub fn load_project(app: &mut VantaApp, path: &str) -> Result<()> {
    let conn = Connection::open(path)?;

    // 1. Load History
    let mut stmt = conn.prepare("SELECT id, method, url, status FROM history")?;
    let history_iter = stmt.query_map([], |row| {
        Ok(HistoryItem {
            id: row.get(0)?,
            method: row.get(1)?,
            url: row.get(2)?,
            status: row.get(3)?,
        })
    })?;

    app.history.clear();
    for item in history_iter {
        app.history.push(item?);
    }

    // 2. Load Scope
    let mut stmt = conn.prepare("SELECT domain FROM scope")?;
    let scope_iter = stmt.query_map([], |row| {
        Ok(row.get::<_, String>(0)?)
    })?;

    app.scope_domains.clear();
    for domain in scope_iter {
        app.scope_domains.push(domain?);
    }
    
    // 3. Load Findings
    let mut stmt = conn.prepare("SELECT url, param, vuln_type, payload, evidence, severity FROM findings")?;
    let findings_iter = stmt.query_map([], |row| {
        Ok(ActiveScanFinding {
            url: row.get(0)?,
            param: row.get(1)?,
            vuln_type: row.get(2)?,
            payload: row.get(3)?,
            evidence: row.get(4)?,
            severity: row.get(5)?,
        })
    })?;
    
    app.activescan_findings.clear();
    for finding in findings_iter {
        app.activescan_findings.push(finding?);
    }

    // 4. Load Sitemap
    // Only verify table exists first
    let mut stmt = conn.prepare("SELECT data FROM sitemap LIMIT 1")?;
    let mut rows = stmt.query([])?;
    
    if let Some(row) = rows.next()? {
        let json: String = row.get(0)?;
        if let Ok(root) = serde_json::from_str(&json) {
            app.sitemap_root = root;
        }
    }

    Ok(())
}
