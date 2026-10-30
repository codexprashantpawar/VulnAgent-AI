"""Checks for missing/misconfigured security HTTP headers."""
import requests

EXPECTED_HEADERS = {
    "Content-Security-Policy": "Prevents XSS by restricting script sources",
    "X-Content-Type-Options": "Should be 'nosniff' to stop MIME sniffing",
    "X-Frame-Options": "Prevents clickjacking via iframes (or use CSP frame-ancestors)",
    "Strict-Transport-Security": "Forces HTTPS (only relevant once you deploy off localhost)",
    "Referrer-Policy": "Controls how much referrer info leaks to other sites",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, etc.)",
}


def run(url, timeout=8):
    findings = []
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        return [{
            "severity": "info",
            "title": "Could not reach target",
            "detail": f"{url} -> {e}",
        }]

    for header, why in EXPECTED_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "severity": "medium",
                "title": f"Missing header: {header}",
                "detail": why,
                "fix": f"Add '{header}' to your server/middleware response headers.",
            })

    server_header = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
    if server_header:
        findings.append({
            "severity": "low",
            "title": "Server/framework version disclosed",
            "detail": f"Response reveals: {server_header}",
            "fix": "Remove or mask the Server/X-Powered-By header in production config.",
        })

    if not findings:
        findings.append({"severity": "ok", "title": "Security headers look good", "detail": ""})

    return findings
