"""
Authentication hardening checks.

IMPORTANT: Nothing here guesses or brute-forces a real account's
password. Rate-limit testing uses one fixed, clearly-fake dummy
credential, sent a handful of times, purely to confirm your API
throttles/locks repeated failed attempts. That's the test -- not
breaking into an account.
"""
import time
import json as json_lib
import requests

# Classic comment-based SQLi login-bypass payloads. The '--' and '#' and '/*'
# are SQL comment markers -- they comment out the rest of the query (usually
# the password check), so the login succeeds on username alone if the query
# is built by string concatenation instead of parameters.
SQLI_LOGIN_BYPASS_PAYLOADS = [
    ("admin'--", "comment"),       # classic: comments out password check after 'admin'
    ("admin' --", "comment"),      # same, with a space before the comment marker
    ("admin' #", "comment"),       # MySQL-style comment marker
    ("admin'/*", "comment"),       # block-comment style
    ("' OR '1'='1'--", "tautology"),  # bypasses without needing to know a valid username
    ("' OR 1=1--", "tautology"),
    ("admin'; --", "comment"),
]


def check_sqli_login_bypass(login_url, timeout=8, user_field="username", pass_field="password"):
    """
    POSTs classic comment-based/tautology SQLi payloads as the USERNAME
    (with an arbitrary password) against your real login endpoint, and
    checks whether any of them return a successful-login indicator
    (token/jwt in the response). This tests the password FIELD too,
    implicitly -- if the backend is vulnerable, it never even needs to
    check the password value because the injected comment strips that
    clause from the query entirely.
    """
    findings = []
    successes = []

    for payload, kind in SQLI_LOGIN_BYPASS_PAYLOADS:
        try:
            resp = requests.post(
                login_url,
                json={user_field: payload, pass_field: "anything_here_123"},
                timeout=timeout,
            )
        except requests.RequestException:
            continue

        success = False
        if resp.status_code == 200:
            try:
                body = resp.json()
                text = json_lib.dumps(body).lower()
                if "token" in text or "jwt" in text or "accesstoken" in text:
                    success = True
            except Exception:
                pass

        if success:
            successes.append((payload, kind))

    if successes:
        findings.append({
            "severity": "high",
            "title": "SQLi login bypass via comment/tautology payload succeeded",
            "detail": f"Username {successes[0][0]!r} returned an auth token without a valid password -- "
                      f"{len(successes)} of {len(SQLI_LOGIN_BYPASS_PAYLOADS)} payloads worked.",
            "fix": "Use parameterized queries / EF Core LINQ instead of building the login WHERE clause "
                   "by string concatenation. A payload like \"admin'--\" only works if raw SQL text is "
                   "built from the username field directly.",
        })
    else:
        findings.append({
            "severity": "ok",
            "title": "SQLi login bypass payloads did not succeed",
            "detail": f"Tried {len(SQLI_LOGIN_BYPASS_PAYLOADS)} comment/tautology payloads on username+password, none bypassed login.",
        })
    return findings


def check_rate_limiting(login_url, dummy_user, dummy_pass, attempts, window_seconds,
                         timeout=8, user_field="username", pass_field="password"):
    findings = []
    statuses = []
    start = time.time()

    for i in range(attempts):
        try:
            resp = requests.post(
                login_url,
                json={user_field: dummy_user, pass_field: dummy_pass},
                timeout=timeout,
            )
            statuses.append(resp.status_code)
        except requests.RequestException as e:
            findings.append({"severity": "info", "title": "Login endpoint unreachable", "detail": str(e)})
            return findings

    elapsed = time.time() - start
    blocked = any(s in (429, 423) for s in statuses)  # Too Many Requests / Locked

    if not blocked:
        findings.append({
            "severity": "high",
            "title": "No rate limiting / lockout detected on login",
            "detail": f"{attempts} failed attempts in {elapsed:.1f}s all returned normally "
                      f"(statuses: {statuses}). A real attacker could brute-force at scale.",
            "fix": "Add rate limiting (e.g. ASP.NET Core rate-limiting middleware) and/or "
                   "account lockout after N failed attempts, plus CAPTCHA after a few failures.",
        })
    else:
        findings.append({
            "severity": "ok",
            "title": "Rate limiting detected on login endpoint",
            "detail": f"Statuses observed: {statuses}",
        })

    return findings


def check_error_message_leakage(login_url, timeout=8, user_field="username", pass_field="password"):
    """Confirms the API doesn't reveal whether a USERNAME exists vs wrong password."""
    findings = []
    try:
        resp_unknown_user = requests.post(
            login_url, json={user_field: "definitely_not_a_real_user_xyz", pass_field: "whatever123"},
            timeout=timeout,
        )
        resp_bad_pass = requests.post(
            login_url, json={user_field: "definitely_not_a_real_user_xyz", pass_field: "different_pw"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        return [{"severity": "info", "title": "Login endpoint unreachable", "detail": str(e)}]

    if resp_unknown_user.text != resp_bad_pass.text or resp_unknown_user.status_code != resp_bad_pass.status_code:
        findings.append({
            "severity": "medium",
            "title": "Login responses differ in a way that may leak username validity",
            "detail": "Different requests to the same bogus identity returned different responses "
                      "-- check it isn't distinguishing 'user not found' vs 'wrong password'.",
            "fix": "Always return a generic 'invalid credentials' message/status regardless of "
                   "whether the username exists.",
        })
    else:
        findings.append({"severity": "ok", "title": "Login error messages appear generic", "detail": ""})

    return findings


def check_protected_endpoints(api_base, endpoints, timeout=8):
    findings = []
    for path in endpoints:
        url = api_base.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=timeout)  # no auth header sent
        except requests.RequestException as e:
            findings.append({"severity": "info", "title": f"Unreachable: {path}", "detail": str(e)})
            continue

        if resp.status_code in (200, 201):
            findings.append({
                "severity": "high",
                "title": f"Endpoint accessible without authentication: {path}",
                "detail": f"Request with no auth token returned {resp.status_code}.",
                "fix": "Add [Authorize] attribute (ASP.NET) / auth middleware to this route.",
            })
        elif resp.status_code in (401, 403):
            findings.append({"severity": "ok", "title": f"{path} correctly requires auth", "detail": ""})
        else:
            findings.append({
                "severity": "info",
                "title": f"Unexpected status on {path}",
                "detail": f"Got {resp.status_code}, expected 401/403.",
            })
    return findings


def check_weak_password_policy(signup_url, weak_passwords, timeout=8, user_field="username", pass_field="password"):
    """Tests whether YOUR signup form rejects obviously weak passwords."""
    findings = []
    for pw in weak_passwords:
        try:
            resp = requests.post(
                signup_url,
                json={user_field: f"policytest_{pw}", pass_field: pw, "email": f"policytest_{pw}@example.com"},
                timeout=timeout,
            )
        except requests.RequestException as e:
            findings.append({"severity": "info", "title": "Signup endpoint unreachable", "detail": str(e)})
            return findings

        if resp.status_code in (200, 201):
            findings.append({
                "severity": "medium",
                "title": f"Weak password accepted: '{pw}'",
                "detail": "Signup succeeded with a commonly-breached password.",
                "fix": "Enforce a minimum length + complexity rule, and check new passwords "
                       "against a breached-password list (e.g. Have I Been Pwned's k-anonymity API).",
            })
    if not findings:
        findings.append({"severity": "ok", "title": "Weak passwords were rejected", "detail": ""})
    return findings
