#!/usr/bin/env python3
"""
Local App Security Auditor
===========================
Scans YOUR OWN local app (Next.js frontend + .NET Web API + SQL Server)
for common misconfigurations and vulnerability symptoms, then produces
a prioritized, explained report with suggested fixes.

SCOPE: localhost / apps you own only. See config.py for the legal note.

Usage:
    pip install -r requirements.txt
    python main.py
"""
import os
import config
from modules import headers_check, injection_check, auth_check, cookies_cors_check, dependency_check
import ai_analyzer
import report


def main():
    all_findings = []

    print("[*] Checking security headers (frontend)...")
    all_findings += tag(headers_check.run(config.FRONTEND_URL, config.REQUEST_TIMEOUT), "Headers/Frontend")

    print("[*] Checking security headers (API)...")
    all_findings += tag(headers_check.run(config.API_BASE_URL, config.REQUEST_TIMEOUT), "Headers/API")

    backend_login_url = config.API_BASE_URL.rstrip("/") + config.BACKEND_LOGIN_ENDPOINT
    frontend_login_url = config.FRONTEND_URL.rstrip("/") + config.FRONTEND_LOGIN_ENDPOINT
    uf, pf = config.LOGIN_USERNAME_FIELD, config.LOGIN_PASSWORD_FIELD

    print("[*] Probing for SQLi/XSS symptoms on backend login endpoint...")
    all_findings += tag(injection_check.check_sqli(backend_login_url, uf, config.REQUEST_TIMEOUT), "Injection")
    all_findings += tag(injection_check.check_reflected_xss(backend_login_url, uf, config.REQUEST_TIMEOUT), "Injection")

    print("[*] Trying SQLi login bypass (admin'--, tautology payloads) on backend...")
    all_findings += tag(auth_check.check_sqli_login_bypass(
        backend_login_url, config.REQUEST_TIMEOUT, user_field=uf, pass_field=pf
    ), "Auth / SQLi")

    print("[*] Checking login rate limiting on backend (dummy credentials only)...")
    all_findings += tag(auth_check.check_rate_limiting(
        backend_login_url, config.DUMMY_USERNAME, config.DUMMY_PASSWORD,
        config.RATE_LIMIT_ATTEMPTS, config.RATE_LIMIT_WINDOW_SECONDS, config.REQUEST_TIMEOUT,
        user_field=uf, pass_field=pf,
    ), "Auth")

    print("[*] Checking login error-message leakage on backend...")
    all_findings += tag(auth_check.check_error_message_leakage(
        backend_login_url, config.REQUEST_TIMEOUT, user_field=uf, pass_field=pf
    ), "Auth")

    print("[*] Checking protected endpoints require auth...")
    all_findings += tag(auth_check.check_protected_endpoints(
        config.API_BASE_URL, config.PROTECTED_ENDPOINTS, config.REQUEST_TIMEOUT
    ), "Auth")

    print("[*] Checking signup password policy...")
    signup_url = config.API_BASE_URL.rstrip("/") + config.API_SIGNUP_ENDPOINT
    all_findings += tag(auth_check.check_weak_password_policy(
        signup_url, config.WEAK_PASSWORDS_TO_REJECT, config.REQUEST_TIMEOUT, user_field=uf, pass_field=pf
    ), "Auth")

    print("[*] Checking session cookie flags (frontend login route, which sets the cookies)...")
    all_findings += tag(cookies_cors_check.check_cookies(frontend_login_url, config.REQUEST_TIMEOUT), "Cookies")

    print("[*] Checking CORS configuration on backend...")
    all_findings += tag(cookies_cors_check.check_cors(backend_login_url, config.REQUEST_TIMEOUT), "CORS")

    print("[*] Reading dependency manifests...")
    npm_deps = dependency_check.read_package_json("package.json")
    all_findings += tag(dependency_check.summarize(npm_deps, "npm"), "Dependencies")
    csproj_deps = dependency_check.read_csproj(".")
    all_findings += tag(dependency_check.summarize(csproj_deps, "NuGet"), "Dependencies")

    all_findings = ai_analyzer.prioritize(all_findings)
    summary_text = ai_analyzer.summarize(all_findings)

    out_dir = config.REPORT_DIR
    json_path = report.write_json(all_findings, out_dir)
    html_path = report.write_html(all_findings, summary_text, out_dir)

    print(f"\n[+] Done. {len(all_findings)} total findings.")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")
    print("\n" + summary_text)


def tag(findings, category):
    for f in findings:
        f["category"] = category
    return findings


if __name__ == "__main__":
    main()
