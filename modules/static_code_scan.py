"""
Static source-code scanner (SAST-lite).

This is the "how real researchers actually find bugs" approach: instead
of poking a running server, it reads YOUR source files and flags known-
risky patterns -- the same category of thing tools like Semgrep, CodeQL,
and SonarQube do, just a lightweight regex-based version you can run
locally with no account/cloud upload needed.

Scope: only ever point this at directories you own. It reads files, it
doesn't send anything anywhere.
"""
import os
import re

# Each pattern: (name, regex, severity, explanation, fix)
CSHARP_PATTERNS = [
    (
        "Possible SQL built by string concatenation/interpolation",
        re.compile(r'(SqlCommand|ExecuteSqlRaw|FromSqlRaw)\s*\(\s*(\$"|["\'].*\+|.*\+.*["\'])', re.IGNORECASE),
        "high",
        "Building SQL with string concatenation or interpolation instead of parameters is the #1 cause of SQL injection.",
        "Use parameterized queries: `SqlCommand(\"...WHERE id=@id\", ...); cmd.Parameters.AddWithValue(\"@id\", id);` "
        "or EF Core's `FromSqlInterpolated` which auto-parameterizes.",
    ),
    (
        "Weak hash algorithm (MD5/SHA1)",
        re.compile(r'\b(MD5|SHA1)\.Create\(\)', re.IGNORECASE),
        "high",
        "MD5 and SHA1 are broken for password hashing (fast + collision-prone).",
        "Use `Rfc2898DeriveBytes`/PBKDF2, BCrypt.Net, or ASP.NET Core Identity's built-in password hasher.",
    ),
    (
        "Insecure deserialization (BinaryFormatter)",
        re.compile(r'\bBinaryFormatter\b'),
        "high",
        "BinaryFormatter is deprecated and exploitable for remote code execution via crafted payloads.",
        "Use System.Text.Json or a safe serializer; avoid deserializing untrusted data with BinaryFormatter entirely.",
    ),
    (
        "CORS allows any origin in code",
        re.compile(r'\.AllowAnyOrigin\s*\(\s*\)'),
        "medium",
        "AllowAnyOrigin() combined with credentials is a common misconfiguration.",
        "Use `.WithOrigins(\"https://yourfrontend.com\")` with an explicit allow-list instead.",
    ),
    (
        "Hardcoded secret/connection string",
        re.compile(r'(password|pwd|secret|apikey|api_key)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "high",
        "A credential appears hardcoded in source rather than loaded from config/secrets.",
        "Move to appsettings.Development.json (gitignored), environment variables, or a secrets manager "
        "(Azure Key Vault, dotnet user-secrets).",
    ),
    (
        "Missing [Authorize] near [HttpGet]/[HttpPost] in controller",
        re.compile(r'\[Http(Get|Post|Put|Delete)\][^\n]*\n(?!\s*\[Authorize\])', re.MULTILINE),
        "info",
        "An endpoint may be missing an [Authorize] attribute -- verify this route is meant to be public.",
        "Add `[Authorize]` above the action, or `[AllowAnonymous]` if it's intentionally public.",
    ),
    (
        "AWS access key pattern in source",
        re.compile(r'AKIA[0-9A-Z]{16}'),
        "high",
        "Matches the AWS access key ID format -- if real and committed, it's a live cloud-credential leak "
        "(this is exactly the 'protect secrets' failure mode in the Hugging Face/ConnectWise incidents).",
        "Revoke the key in AWS IAM immediately if real, move to environment variables or a secrets manager.",
    ),
    (
        "Azure/connection-string-style secret",
        re.compile(r'(DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{20,}', re.IGNORECASE),
        "high",
        "Looks like an Azure storage connection string with an embedded account key.",
        "Move to appsettings with user-secrets/Key Vault; never commit connection strings with keys.",
    ),
    (
        "JWT signing secret hardcoded",
        re.compile(r'(jwt.*secret|signingkey|secretkey)\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        "high",
        "A JWT signing key in source means anyone with repo access can forge valid tokens for any user.",
        "Load from environment/secrets manager; rotate the key if it was ever committed to version control.",
    ),
    (
        "Exception details exposed to client (potential info leak)",
        re.compile(r'\.Message\s*\)\s*;?\s*$|return\s+(BadRequest|Ok)\s*\(\s*ex\b', re.IGNORECASE | re.MULTILINE),
        "low",
        "Returning raw exception details to the client can leak stack traces, file paths, or internal logic "
        "(relevant to PHP2Shell's lesson: verbose runtime errors reveal more than they should to attackers).",
        "Log the full exception server-side; return a generic error message to the client.",
    ),
]

JS_TS_PATTERNS = [
    (
        "dangerouslySetInnerHTML usage",
        re.compile(r'dangerouslySetInnerHTML'),
        "high",
        "Renders raw HTML, bypassing React's automatic escaping -- classic stored/reflected XSS vector if the content includes user input.",
        "Avoid it, or sanitize with DOMPurify first: `dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}`.",
    ),
    (
        "eval() or new Function() usage",
        re.compile(r'\beval\s*\(|\bnew\s+Function\s*\('),
        "high",
        "Executes arbitrary strings as code -- dangerous if any part of the string is user-influenced.",
        "Avoid eval entirely; use JSON.parse for data, or a proper parser/interpreter for the specific need.",
    ),
    (
        "Hardcoded secret/API key in frontend code",
        re.compile(r'(apiKey|api_key|secret|password)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']', re.IGNORECASE),
        "high",
        "Frontend/client code ships to the browser -- any secret here is visible to every visitor.",
        "Move secret-requiring calls to a server-side API route; only ever expose public/anon keys to the client.",
    ),
    (
        "Token stored in localStorage/sessionStorage",
        re.compile(r'(localStorage|sessionStorage)\.setItem\([^)]*(token|jwt|auth)', re.IGNORECASE),
        "medium",
        "Tokens in localStorage are readable by any injected script (XSS) -- less safe than httpOnly cookies.",
        "Prefer httpOnly, Secure, SameSite cookies for auth tokens (you're already doing this for login -- "
        "make sure nothing else stores a token in localStorage as a shortcut).",
    ),
    (
        "console.log of likely sensitive data",
        re.compile(r'console\.(log|debug)\([^)]*\b(password|token|secret|apikey)\b', re.IGNORECASE),
        "low",
        "Logging credentials/tokens can leak them into browser devtools history or server logs.",
        "Remove or redact before logging; never log raw credentials/tokens even in development.",
    ),
]

SKIP_DIRS = {"node_modules", ".git", ".next", "bin", "obj", "__pycache__", "dist", "build"}


def _walk_files(root_dir, extensions):
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if any(fname.endswith(ext) for ext in extensions):
                yield os.path.join(dirpath, fname)


def scan_directory(root_dir, patterns, extensions, max_findings_per_pattern=5):
    findings = []
    pattern_hit_counts = {}

    if not os.path.isdir(root_dir):
        return [{
            "severity": "info",
            "title": f"Directory not found: {root_dir}",
            "detail": "Check the path you entered.",
        }]

    for filepath in _walk_files(root_dir, extensions):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        for name, regex, severity, explanation, fix in patterns:
            count_key = name
            if pattern_hit_counts.get(count_key, 0) >= max_findings_per_pattern:
                continue
            for match in regex.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                rel_path = os.path.relpath(filepath, root_dir)
                findings.append({
                    "severity": severity,
                    "title": name,
                    "detail": f"{rel_path}:{line_no} -- {explanation}",
                    "fix": fix,
                })
                pattern_hit_counts[count_key] = pattern_hit_counts.get(count_key, 0) + 1
                if pattern_hit_counts[count_key] >= max_findings_per_pattern:
                    break

    if not findings:
        findings.append({
            "severity": "ok",
            "title": f"No known-risky patterns found in {root_dir}",
            "detail": f"Scanned {sum(1 for _ in _walk_files(root_dir, extensions))} file(s). "
                      "This covers common patterns only -- not a substitute for a full audit.",
        })

    return findings


def scan_dotnet_source(root_dir):
    return scan_directory(root_dir, CSHARP_PATTERNS, [".cs"])


def scan_js_ts_source(root_dir):
    return scan_directory(root_dir, JS_TS_PATTERNS, [".js", ".jsx", ".ts", ".tsx"])
