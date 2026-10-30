#!/usr/bin/env python3
"""
Local web dashboard for the Security Auditor.

Runs a small Flask server on localhost that lets you trigger a scan from
a browser UI instead of the command line, and view results live.

Why a backend is needed (not just a static HTML page):
- Browsers can't read httpOnly cookies (by design) -- we need a real
  HTTP client (Python's `requests`) to inspect cookie flags.
- Browsers block most cross-origin probe requests via CORS -- a server
  process doesn't have that restriction, which is required to actually
  test your API's CORS config in the first place.
- Rate-limit testing needs precise request timing, which a script
  controls far more reliably than client-side JS.

Scope reminder: this still only scans targets you own/control. Entering
a non-localhost URL requires an explicit authorization confirmation.

Run:
    pip install flask
    python dashboard.py
Then open http://localhost:7000
"""
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

import config
from modules import headers_check, injection_check, auth_check, cookies_cors_check, dependency_check, static_code_scan, lab_exploits
import ai_analyzer

app = Flask(__name__)

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def is_local(url: str) -> bool:
    try:
        return urlparse(url).hostname in LOCAL_HOSTS
    except Exception:
        return False


def tag(findings, category):
    for f in findings:
        f["category"] = category
    return findings


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_frontend=config.FRONTEND_URL,
        default_api=config.API_BASE_URL,
    )


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    frontend_url = data.get("frontend_url", "").rstrip("/")
    api_url = data.get("api_url", "").rstrip("/")
    login_path = data.get("login_path") or config.BACKEND_LOGIN_ENDPOINT
    authorized = data.get("authorized", False)
    llm_provider = data.get("llm_provider") or None
    llm_api_key = data.get("llm_api_key") or None
    dotnet_source_path = data.get("dotnet_source_path") or None
    frontend_source_path = data.get("frontend_source_path") or None

    # Scope gate: any non-local target requires explicit authorization checkbox
    if (not is_local(frontend_url) or not is_local(api_url)) and not authorized:
        return jsonify({
            "error": "non_local_target",
            "message": "One or both targets aren't localhost. This tool only scans "
                       "systems you own or are explicitly authorized to test. "
                       "Confirm authorization to proceed."
        }), 400

    all_findings = []
    uf, pf = config.LOGIN_USERNAME_FIELD, config.LOGIN_PASSWORD_FIELD
    backend_login_url = api_url + login_path

    all_findings += tag(headers_check.run(frontend_url, config.REQUEST_TIMEOUT), "Headers/Frontend")
    all_findings += tag(headers_check.run(api_url, config.REQUEST_TIMEOUT), "Headers/API")
    all_findings += tag(injection_check.check_sqli(backend_login_url, uf, config.REQUEST_TIMEOUT), "Injection")
    all_findings += tag(injection_check.check_reflected_xss(backend_login_url, uf, config.REQUEST_TIMEOUT), "Injection")
    all_findings += tag(auth_check.check_sqli_login_bypass(
        backend_login_url, config.REQUEST_TIMEOUT, user_field=uf, pass_field=pf
    ), "Auth / SQLi")
    all_findings += tag(auth_check.check_rate_limiting(
        backend_login_url, config.DUMMY_USERNAME, config.DUMMY_PASSWORD,
        config.RATE_LIMIT_ATTEMPTS, config.RATE_LIMIT_WINDOW_SECONDS, config.REQUEST_TIMEOUT,
        user_field=uf, pass_field=pf,
    ), "Auth")
    all_findings += tag(auth_check.check_error_message_leakage(
        backend_login_url, config.REQUEST_TIMEOUT, user_field=uf, pass_field=pf
    ), "Auth")
    all_findings += tag(auth_check.check_protected_endpoints(
        api_url, config.PROTECTED_ENDPOINTS, config.REQUEST_TIMEOUT
    ), "Auth")
    all_findings += tag(cookies_cors_check.check_cookies(frontend_url, config.REQUEST_TIMEOUT), "Cookies")
    all_findings += tag(cookies_cors_check.check_cors(backend_login_url, config.REQUEST_TIMEOUT), "CORS")

    if dotnet_source_path:
        all_findings += tag(static_code_scan.scan_dotnet_source(dotnet_source_path), "Source Code (.NET)")
        all_findings += tag(dependency_check.run_dotnet_vulnerable_check(dotnet_source_path), "Dependencies (.NET, real CVEs)")
    if frontend_source_path:
        all_findings += tag(static_code_scan.scan_js_ts_source(frontend_source_path), "Source Code (Next.js)")
        all_findings += tag(dependency_check.run_npm_audit(frontend_source_path), "Dependencies (npm, real CVEs)")

    all_findings = ai_analyzer.prioritize(all_findings)
    summary, ai_error = ai_analyzer.summarize(all_findings, provider=llm_provider, api_key=llm_api_key)
    checklist = ai_analyzer.build_checklist(all_findings)

    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return jsonify({
        "findings": all_findings,
        "summary": summary,
        "ai_error": ai_error,
        "counts": counts,
        "checklist": checklist,
    })


KNOWN_TRAINING_APPS = {"juice-shop", "dvwa", "webgoat", "mutillidae", "bwapp"}


@app.route("/lab_scan", methods=["POST"])
def lab_scan():
    """
    Runs ACTIVE exploit attempts (SQLi bypass, IDOR, JWT inspection).
    Gated: requires both a recognized training-app selection AND the
    explicit confirmation checkbox. This route intentionally does NOT
    accept arbitrary production targets -- that's what /scan is for,
    and it only ever does passive/symptom checks.
    """
    data = request.get_json(force=True)
    target_url = data.get("target_url", "").rstrip("/")
    app_type = data.get("app_type", "")
    confirmed = data.get("confirmed_training_target", False)

    if app_type not in KNOWN_TRAINING_APPS:
        return jsonify({
            "error": "unrecognized_target",
            "message": "Lab Mode only runs against recognized training apps "
                       "(OWASP Juice Shop, DVWA, WebGoat, Mutillidae, bWAPP)."
        }), 400

    if not confirmed:
        return jsonify({
            "error": "not_confirmed",
            "message": "Confirm this is a training app you're running locally for practice."
        }), 400

    if not is_local(target_url):
        return jsonify({
            "error": "non_local_lab_target",
            "message": "Lab Mode only runs against localhost. Run your training app locally."
        }), 400

    findings = []
    login_url = target_url + "/rest/user/login" if app_type == "juice-shop" else target_url + "/login"
    findings += tag(lab_exploits.attempt_sqli_login_bypass(login_url), "Active Exploit: SQLi")

    if app_type == "juice-shop":
        findings += tag(
            lab_exploits.test_idor(target_url, "/rest/basket/{id}", range(1, 8)),
            "Active Exploit: IDOR",
        )

    findings = ai_analyzer.prioritize(findings)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return jsonify({"findings": findings, "counts": counts})


if __name__ == "__main__":
    print("[*] Dashboard running at http://localhost:7000")
    app.run(host="127.0.0.1", port=7000, debug=False)
