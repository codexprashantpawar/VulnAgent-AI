# 🛡️ VulnAgent AI

**An AI-assisted application security auditor that discovers vulnerabilities, identifies security misconfigurations, and helps developers build more secure applications.**

VulnAgent AI analyzes your own locally hosted or explicitly authorized web applications, identifies potential security weaknesses, and generates prioritized reports with practical explanations and remediation steps.

### 🎯 Supported Stack

- **Frontend:** Next.js
- **Backend:** .NET Web API / ASP.NET Core
- **Database:** Microsoft SQL Server

### 🔍 Security Checks

| Module | What It Detects |
|---|---|
| Security Headers | Missing CSP, HSTS, X-Frame-Options, version disclosure |
| SQL Injection | SQL error leakage, injection response anomalies, and multiple SQL injection test cases |
| XSS Detection | Potential reflected cross-site scripting |
| Authentication | Login rate limiting, weak-password acceptance, generic error handling |
| Authorization | Unauthorized access to protected endpoints |
| Cookies & CORS | Insecure cookie flags, wildcard and reflected CORS policies |
| Dependencies | npm and NuGet package versions for vulnerability analysis |

### ⚙️ How It Works

1. Connects to your configured local application.
2. Runs automated security checks.
3. Analyzes HTTP responses and application behavior.
4. Identifies and categorizes potential vulnerabilities.
5. Generates prioritized security findings.
6. Provides plain-English explanations and recommended fixes.

### 🚀 Setup

```bash
cd security_scanner
pip install -r requirements.txt
```

Configure your application URLs and API endpoints in `config.py`.

### ▶️ Run

```bash
python main.py
```

### 📊 Reports

Generated reports:

- `reports/findings.json` — Structured security findings.
- `reports/report.html` — Readable security audit report.

### 🧠 AI Capabilities

AI-assisted analysis helps translate technical findings into understandable security explanations and actionable remediation guidance.

### 🔒 Responsible Security

VulnAgent AI is designed exclusively for localhost applications you own or systems for which you have explicit written authorization.

It does not perform password brute-forcing or unauthorized exploitation.

### 🚀 Future Enhancements

- Automated CVE detection for npm and NuGet dependencies.
- Deeper API security testing.
- Intelligent vulnerability correlation and risk analysis.
- AI-powered root cause analysis.
- Automated code-level remediation suggestions.
- Agentic security investigation workflows.
- Interactive security dashboard.

**Build securely. Detect early. Fix confidently.**