use crate::core::models::ActiveScanFinding;
use chrono::Local;

pub fn generate_html_report(findings: &[ActiveScanFinding]) -> String {
    let date = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let finding_count = findings.len();

    let mut findings_html = String::new();
    for (idx, finding) in findings.iter().enumerate() {
        findings_html.push_str(&format!(
            r#"
            <div class="finding">
                <h3>#{idx} {vuln_type} - {severity}</h3>
                <div class="details">
                    <p><strong>URL:</strong> <a href="{url}">{url}</a></p>
                    <p><strong>Parameter:</strong> <code>{param}</code></p>
                    <p><strong>Payload:</strong> <code>{payload}</code></p>
                    <div class="evidence">
                        <strong>Evidence:</strong>
                        <pre>{evidence}</pre>
                    </div>
                </div>
            </div>
            "#,
            idx = idx + 1,
            vuln_type = finding.vuln_type,
            severity = finding.severity,
            url = finding.url,
            param = finding.param,
            payload = html_escape(&finding.payload),
            evidence = html_escape(&finding.evidence)
        ));
    }

    format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VantaStalker Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; line-height: 1.6; margin: 0; padding: 20px; }}
        .container {{ max_width: 900px; margin: 0 auto; background: #fff; padding: 40px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; }}
        header {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ color: #2d3748; margin: 0; }}
        .meta {{ color: #718096; font-size: 0.9em; margin-top: 5px; }}
        .summary {{ background: #ebf8ff; border-left: 4px solid #4299e1; padding: 15px; margin-bottom: 30px; border-radius: 4px; }}
        .finding {{ background: #fff; border: 1px solid #e2e8f0; margin-bottom: 20px; border-radius: 6px; overflow: hidden; }}
        .finding h3 {{ background: #2d3748; color: #fff; margin: 0; padding: 10px 15px; font-size: 1.1em; }}
        .finding .details {{ padding: 15px; }}
        .finding p {{ margin: 5px 0; }}
        code {{ background: #edf2f7; padding: 2px 5px; border-radius: 3px; font-family: 'Consolas', monospace; color: #c53030; }}
        pre {{ background: #2d3748; color: #e2e8f0; padding: 10px; border-radius: 4px; overflow-x: auto; }}
        a {{ color: #4299e1; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>VantaStalker Security Scan Report</h1>
            <div class="meta">Generated on {date}</div>
        </header>

        <div class="summary">
            <strong>Scan Summary:</strong> Found {finding_count} vulnerabilities.
        </div>

        <div class="findings-list">
            {findings_html}
        </div>
    </div>
</body>
</html>
        "#,
        date = date,
        finding_count = finding_count,
        findings_html = findings_html
    )
}

fn html_escape(input: &str) -> String {
    input.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace("\"", "&quot;")
         .replace("'", "&#39;")
}
