"""Checks session cookie flags and CORS configuration."""
import requests


def check_cookies(url, timeout=8):
    findings = []
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        return [{"severity": "info", "title": "Target unreachable", "detail": str(e)}]

    if not resp.cookies:
        findings.append({"severity": "info", "title": "No cookies set on this response", "detail": ""})
        return findings

    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing 'Secure' flag")
        has_httponly = cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower()
        if not has_httponly:
            issues.append("missing 'HttpOnly' flag")
        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            issues.append("missing 'SameSite' attribute")

        if issues:
            findings.append({
                "severity": "medium",
                "title": f"Cookie '{cookie.name}' misconfigured",
                "detail": ", ".join(issues),
                "fix": "Set cookies with Secure, HttpOnly and SameSite=Strict/Lax "
                       "(in ASP.NET: CookieOptions { HttpOnly=true, Secure=true, SameSite=SameSiteMode.Strict }).",
            })
        else:
            findings.append({"severity": "ok", "title": f"Cookie '{cookie.name}' flags look correct", "detail": ""})

    return findings


def check_cors(api_url, timeout=8):
    findings = []
    try:
        resp = requests.options(
            api_url,
            headers={"Origin": "https://evil-example.com", "Access-Control-Request-Method": "GET"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return [{"severity": "info", "title": "CORS preflight unreachable", "detail": str(e)}]

    allow_origin = resp.headers.get("Access-Control-Allow-Origin")
    allow_creds = resp.headers.get("Access-Control-Allow-Credentials")

    if allow_origin == "*":
        sev = "high" if allow_creds == "true" else "medium"
        findings.append({
            "severity": sev,
            "title": "CORS allows any origin (*)",
            "detail": f"Access-Control-Allow-Origin=* (credentials allowed: {allow_creds})",
            "fix": "Restrict Access-Control-Allow-Origin to your known frontend domain(s) "
                   "instead of a wildcard, especially since the API handles auth.",
        })
    elif allow_origin == "https://evil-example.com":
        findings.append({
            "severity": "high",
            "title": "CORS reflects arbitrary Origin header",
            "detail": "API echoed back an untrusted Origin as allowed.",
            "fix": "Use an explicit allow-list of trusted origins, never reflect the request Origin.",
        })
    else:
        findings.append({"severity": "ok", "title": "CORS origin policy looks restricted", "detail": f"Origin: {allow_origin}"})

    return findings
