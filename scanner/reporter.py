import json
import os
from datetime import datetime

def save_json_report(findings, filename="report.json"):
    """Saves scan findings to a JSON file."""
    report_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings
    }
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"[+] JSON report successfully saved to {filename}")

def calculate_risk_score(findings):
    """
    Calculates an overall environment risk score based on finding severities.
    Starts at 100 (secure) and subtracts points per finding.
    """
    score = 100
    weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3
    }
    
    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        score -= weights.get(severity, 5)
        
    # Ensure score doesn't drop below 0
    final_score = max(0, score)
    
    if final_score >= 90:
        grade = "A (Low Risk)"
        badge_class = "badge-low"
    elif final_score >= 75:
        grade = "B (Moderate Risk)"
        badge_class = "badge-low"
    elif final_score >= 50:
        grade = "C (High Risk)"
        badge_class = "badge-med"
    else:
        grade = "F (Critical Risk)"
        badge_class = "badge-high"
        
    return final_score, grade, badge_class

def generate_html_report(findings, filename="report.html"):
    """Generates a professional, self-contained HTML security report."""
    
    # Calculate summary statistics
    total = len(findings)
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")
    
    # Calculate Risk Score & Grade
    score, grade, grade_badge_class = calculate_risk_score(findings)

    # Build rows for the findings table
    rows_html = ""
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        badge_cls = "badge-high" if sev in ["HIGH", "CRITICAL"] else ("badge-med" if sev == "MEDIUM" else "badge-low")
        rows_html += f"""
        <tr>
            <td><span class="badge {badge_cls}">{sev}</span></td>
            <td><strong>{f.get('category', 'N/A')}</strong></td>
            <td><code>{f.get('resource', 'N/A')}</code></td>
            <td>{f.get('description', 'N/A')}</td>
            <td>{f.get('remediation', 'Review and secure resource configuration.')}</td>
        </tr>
        """

    # Complete HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CloudProwler Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: auto; background: #1e293b; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ background: #0f172a; padding: 15px; border-radius: 8px; flex: 1; border-left: 4px solid #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }}
        .badge-high {{ background: #ef4444; color: white; }}
        .badge-med {{ background: #f59e0b; color: white; }}
        .badge-low {{ background: #10b981; color: white; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CloudProwler Security Audit Report</h1>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        
        <div class="stats">
            <div class="card"><h3>Total Findings</h3><p style="font-size: 1.5rem; margin: 0;">{total}</p></div>
            <div class="card"><h3>Environment Risk Score</h3><p style="font-size: 1.5rem; margin: 0;">{score} / 100</p></div>
            <div class="card"><h3>Security Grade</h3><p style="font-size: 1.5rem; margin: 0;"><span class="badge {grade_badge_class}">{grade}</span></p></div>
        </div>

        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Target Resource</th>
                    <th>Vulnerability Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML dashboard successfully generated: {filename}")