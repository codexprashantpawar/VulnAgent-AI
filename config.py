"""
Configuration for the Local App Security Auditor.

SCOPE / LEGAL NOTE:
This tool is for scanning applications you OWN or have EXPLICIT WRITTEN
AUTHORIZATION to test (e.g. your own localhost Next.js frontend and
.NET Web API backend). Running this against third-party systems without
permission is illegal in most jurisdictions (CFAA in the US, IT Act in
India, similar laws elsewhere). Do not point TARGET_* at anything you
don't control.
"""

# --- Targets (edit these to match your local setup) ---
FRONTEND_URL = "http://localhost:3000"            # Next.js app
API_BASE_URL = "http://localhost:5259"            # .NET Web API (RaceTrakingAPI)

# Your frontend proxies login through a Next.js API route that ALSO sets
# the httpOnly cookies -- so login/cookie checks should hit the FRONTEND,
# not the raw backend. The backend route itself (/auth/login) is tested
# separately for injection/rate-limit symptoms.
FRONTEND_LOGIN_ENDPOINT = "/api/auth/login"       # your Next.js route.ts path
BACKEND_LOGIN_ENDPOINT = "/auth/login"            # raw .NET route it proxies to
API_SIGNUP_ENDPOINT = "/auth/register"            # adjust if different

# Your login body uses these exact field names (confirmed from your route.ts)
LOGIN_USERNAME_FIELD = "userName"
LOGIN_PASSWORD_FIELD = "password"

# Paths on the API you want to confirm require authentication
PROTECTED_ENDPOINTS = [
    "/api/users/me",
    "/api/races",
]

# --- Rate-limit test settings ---
# Dummy, non-existent credentials only. This checks whether the API
# locks/slows repeated attempts -- it never tries to guess a real
# account's password.
DUMMY_USERNAME = "scanner_test_user_does_not_exist"
DUMMY_PASSWORD = "not_a_real_password_123!"
RATE_LIMIT_ATTEMPTS = 6          # how many dummy attempts to send
RATE_LIMIT_WINDOW_SECONDS = 10   # expected throttling window

# --- Weak password policy check (against your OWN signup form) ---
WEAK_PASSWORDS_TO_REJECT = [
    "123456", "password", "qwerty", "111111", "abc123", "admin"
]

# --- Output ---
REPORT_DIR = "reports"
REQUEST_TIMEOUT = 8
