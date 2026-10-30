"""
Turns raw scanner findings into a prioritized, plain-English summary.

Supports three ways to get a richer AI summary (falls back to a simple
rule-based summary if none are available):
  1. A provider + api_key passed in directly (e.g. from the dashboard UI)
  2. ANTHROPIC_API_KEY env var (Claude)
  3. OPENAI_API_KEY env var (GPT)

Your key is only ever used for this one request to the provider you pick;
this file doesn't store it anywhere.
"""
import os
import json
import requests

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}

PROVIDER_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
}


def prioritize(all_findings):
    return sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))


def rule_based_summary(all_findings):
    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = ["=== Summary ==="]
    for sev in ["high", "medium", "low", "info", "ok"]:
        if sev in counts:
            lines.append(f"{sev.upper()}: {counts[sev]} finding(s)")

    lines.append("\n=== Top priorities ===")
    high_findings = [f for f in all_findings if f["severity"] == "high"]
    if not high_findings:
        lines.append("No high-severity issues found. Review medium findings next.")
    for f in high_findings[:5]:
        lines.append(f"- {f['title']}: {f.get('fix', 'Review manually.')}")

    return "\n".join(lines)


def _build_prompt(all_findings):
    findings_text = json.dumps(
        [{"severity": f["severity"], "title": f["title"], "detail": f.get("detail", "")}
         for f in all_findings if f["severity"] != "ok"],
        indent=2,
    )
    return (
        "You are a security engineer reviewing automated scan results for a "
        "developer's own local app (Next.js frontend + .NET Web API + SQL Server). "
        "Summarize the findings below in plain English, group related issues, "
        "and give a prioritized remediation plan. Do not add any new vulnerabilities "
        "or exploit techniques beyond what's listed -- only explain and prioritize "
        f"what was found.\n\nFindings:\n{findings_text}"
    )


def _call_anthropic(api_key, prompt):
    resp = requests.post(
        PROVIDER_ENDPOINTS["anthropic"],
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": "claude-sonnet-4-6", "max_tokens": 1000, "messages": [{"role": "user", "content": prompt}]},
        timeout=30,
    )
    data = resp.json()
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "Anthropic API error"))
    blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(blocks)


def _call_openai(api_key, prompt):
    resp = requests.post(
        PROVIDER_ENDPOINTS["openai"],
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={"model": "gpt-4o-mini", "max_tokens": 1000, "messages": [{"role": "user", "content": prompt}]},
        timeout=30,
    )
    data = resp.json()
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "OpenAI API error"))
    return data["choices"][0]["message"]["content"]


def _call_gemini(api_key, prompt):
    resp = requests.post(
        f"{PROVIDER_ENDPOINTS['gemini']}?key={api_key}",
        headers={"Content-Type": "application/json"},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=30,
    )
    data = resp.json()
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "Gemini API error"))
    return data["candidates"][0]["content"]["parts"][0]["text"]


def ai_summary(all_findings, provider=None, api_key=None):
    """
    Try a richer AI-written summary. `provider`/`api_key` (from the UI)
    take priority; otherwise falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY
    env vars if set. Returns None (silently) if nothing is configured or
    the call fails, so the caller always has the rule-based summary to fall
    back on.
    """
    if not provider or not api_key:
        if os.environ.get("ANTHROPIC_API_KEY"):
            provider, api_key = "anthropic", os.environ["ANTHROPIC_API_KEY"]
        elif os.environ.get("OPENAI_API_KEY"):
            provider, api_key = "openai", os.environ["OPENAI_API_KEY"]
        else:
            return None, None

    prompt = _build_prompt(all_findings)
    try:
        if provider == "anthropic":
            return _call_anthropic(api_key, prompt), None
        elif provider == "openai":
            return _call_openai(api_key, prompt), None
        elif provider == "gemini":
            return _call_gemini(api_key, prompt), None
        else:
            return None, f"Unknown provider: {provider}"
    except Exception as e:
        return None, str(e)


def summarize(all_findings, provider=None, api_key=None):
    ai_result, error = ai_summary(all_findings, provider, api_key)
    if ai_result:
        return "=== AI-Generated Summary ===\n" + ai_result, None
    return rule_based_summary(all_findings), error


# Maps each finding category/title keyword to one of the standard checklist
# items (patch deps / secure identity / protect secrets / restrict data access /
# isolate untrusted code / log events / incident response), so you can see at
# a glance which of the "7 habits" your app currently covers vs. not.
CHECKLIST_ITEMS = [
    ("Patch runtimes & dependencies", ["vulnerability in", "npm audit", "dotnet", "dependencies found"]),
    ("Secure identity (auth/rate-limit)", ["rate limiting", "authorize", "authentication", "requires auth", "accessible without authentication"]),
    ("Protect secrets", ["secret", "hardcoded", "access key", "connection-string", "jwt signing"]),
    ("Restrict data access (parameterized SQL etc.)", ["sql", "injection", "deserialization"]),
    ("Safe error handling / no info leakage", ["exception", "error leakage", "version disclosed", "exposed to client"]),
    ("Transport & header hardening", ["header", "cors", "cookie"]),
    ("Client-side safety (XSS/eval/storage)", ["xss", "eval", "innerhtml", "localstorage"]),
]


def build_checklist(all_findings):
    """Returns a list of {item, status, count} -- status is 'issues_found',
    'clean', or 'not_checked' depending on whether any findings matched and
    whether they were high/medium severity."""
    results = []
    for item_name, keywords in CHECKLIST_ITEMS:
        matched = [
            f for f in all_findings
            if any(kw in (f.get("title", "") + " " + f.get("detail", "")).lower() for kw in keywords)
        ]
        bad = [f for f in matched if f.get("severity") in ("high", "medium")]
        if not matched:
            status = "not_checked"
        elif bad:
            status = "issues_found"
        else:
            status = "clean"
        results.append({"item": item_name, "status": status, "issue_count": len(bad)})
    return results
