"""Generates a readable HTML report + raw JSON from findings."""
import json
import os
from datetime import datetime

SEVERITY_COLOR = {
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
    "ok": "#16a34a",
}


def write_json(all_findings, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "findings.json")
    with open(path, "w") as f:
        json.dump(all_findings, f, indent=2)
    return path


def write_html(all_findings, summary_text, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = ""
    for f in all_findings:
        color = SEVERITY_COLOR.get(f["severity"], "#6b7280")
        fix = f.get("fix", "")
        rows += f"""
        <tr>
          <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;
              font-size:12px;text-transform:uppercase;">{f['severity']}</span></td>
          <td><strong>{f['title']}</strong><br><span style="color:#555;font-size:14px;">{f.get('detail','')}</span></td>
          <td style="color:#15803d;font-size:14px;">{fix}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Scan Report</title>
<style>
  body {{ font-family: -apple-system, Arial, sans-serif; margin: 40px; background:#fafafa; color:#111; }}
  h1 {{ margin-bottom:0; }}
  .meta {{ color:#666; margin-bottom:24px; }}
  table {{ width:100%; border-collapse: collapse; background:white; }}
  th, td {{ text-align:left; padding:12px; border-bottom:1px solid #eee; vertical-align:top; }}
  th {{ background:#f3f4f6; }}
  pre.summary {{ background:white; padding:16px; border-radius:8px; white-space:pre-wrap; }}
</style></head>
<body>
  <h1>Local App Security Scan Report</h1>
  <div class="meta">Generated {timestamp} &mdash; scope: localhost app(s) only</div>
  <pre class="summary">{summary_text}</pre>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Suggested fix</th></tr>
    {rows}
  </table>
</body></html>"""

    path = os.path.join(out_dir, "report.html")
    with open(path, "w") as f:
        f.write(html)
    return path
