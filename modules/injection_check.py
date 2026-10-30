"""
Safe, non-destructive probes for SQL-injection and XSS *symptoms*.

These payloads are the standard, well-known canaries used by every
mainstream scanner (ZAP, Burp, sqlmap's basic probes) -- they don't
exploit anything, they just check whether input is escaped/parameterized
properly by looking for behavior changes or unescaped reflection.
"""
import requests

SQLI_PROBES = ["'", "' OR '1'='1", "\"", "1;--"]
XSS_PROBE = "<scriptTEST>alert(1)</scriptTEST>"  # broken tag so it can't actually execute if pasted


def check_sqli(url, param_name, timeout=8):
    findings = []
    try:
        baseline = requests.get(url, params={param_name: "baseline_value"}, timeout=timeout)
    except requests.RequestException as e:
        return [{"severity": "info", "title": "Target unreachable", "detail": str(e)}]

    for payload in SQLI_PROBES:
        try:
            resp = requests.get(url, params={param_name: payload}, timeout=timeout)
        except requests.RequestException:
            continue

        error_markers = ["sql syntax", "unclosed quotation", "sqlexception",
                          "microsoft sql", "odbc", "syntax error"]
        body_lower = resp.text.lower()
        if any(marker in body_lower for marker in error_markers):
            findings.append({
                "severity": "high",
                "title": f"Possible SQL error leakage on param '{param_name}'",
                "detail": f"Payload {payload!r} triggered a DB error message in the response.",
                "fix": "Use parameterized queries / an ORM (EF Core) instead of string-built SQL. "
                       "Never concatenate user input into T-SQL.",
            })
        elif resp.status_code != baseline.status_code or len(resp.text) != len(baseline.text):
            findings.append({
                "severity": "medium",
                "title": f"Unusual response change on param '{param_name}'",
                "detail": f"Payload {payload!r} changed status/length vs baseline -- worth manual review.",
                "fix": "Confirm input is validated/parameterized; investigate why output differs.",
            })

    if not findings:
        findings.append({"severity": "ok", "title": f"No SQLi symptoms on '{param_name}'", "detail": ""})
    return findings


def check_reflected_xss(url, param_name, timeout=8):
    findings = []
    try:
        resp = requests.get(url, params={param_name: XSS_PROBE}, timeout=timeout)
    except requests.RequestException as e:
        return [{"severity": "info", "title": "Target unreachable", "detail": str(e)}]

    if XSS_PROBE in resp.text:
        findings.append({
            "severity": "high",
            "title": f"Reflected input not escaped on param '{param_name}'",
            "detail": "Raw payload appeared unescaped in the HTML response.",
            "fix": "Escape/encode all user input on output (React/Next.js does this by default -- "
                   "check for dangerouslySetInnerHTML usage or raw API responses rendered as HTML).",
        })
    else:
        findings.append({"severity": "ok", "title": f"No reflected-XSS symptom on '{param_name}'", "detail": ""})
    return findings
