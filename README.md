# 🛡️ VulnAgent AI

**An AI-assisted, technology-independent application security auditor that discovers vulnerabilities, identifies security misconfigurations, and helps developers build more secure applications.**

VulnAgent AI analyzes locally hosted or explicitly authorized web applications across different technology stacks. It detects potential security weaknesses, evaluates application behavior, and generates prioritized reports with plain-English explanations and practical remediation steps.

### 🌐 Technology Independent

Designed to audit web applications regardless of their underlying technology stack.

- **Frontend:** React, Next.js, Angular, Vue, HTML/CSS/JavaScript and more.
- **Backend:** .NET, Node.js, Python, Java, PHP, Go, Ruby and more.
- **Databases:** SQL Server, PostgreSQL, MySQL, MongoDB and more.
- **Architecture:** REST APIs, traditional web applications and modern web architectures.

*Security coverage depends on the configured endpoints, available responses, and applicable detection techniques.*

### 🔍 Security Checks

| Module | What It Detects |
|---|---|
| Security Headers | Missing CSP, HSTS, X-Frame-Options and version disclosure |
| SQL Injection | SQL error leakage, injection response anomalies and multiple SQL injection test cases |
| XSS Detection | Potential reflected cross-site scripting |
| Authentication | Login rate limiting, weak-password acceptance and generic error handling |
| Authorization | Unauthorized access to protected endpoints |
| Cookies & CORS | Insecure cookie flags, wildcard and reflected CORS policies |
| Dependencies | npm and NuGet package versions for vulnerability analysis |

### ⚙️ How It Works

1. Connects to your configured application.
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

Configure your target URLs and API endpoints in `config.py`.

### ▶️ Run

```bash
python main.py
```

### 📊 Reports

Generated reports:

- `reports/findings.json` — Structured security findings.
- `reports/report.html` — Readable security audit report.

### 🧠 AI Capabilities

AI-assisted analysis helps translate technical findings into understandable security explanations, prioritize risks, and provide actionable remediation guidance.

### 🔒 Responsible Security

VulnAgent AI is designed exclusively for localhost applications you own or systems for which you have explicit written authorization.

It does not perform password brute-forcing or unauthorized exploitation.

### 🛠️ Future Enhancements

- Automated CVE detection for npm, NuGet and other package ecosystems.
- Expanded security testing across different API architectures.
- Intelligent vulnerability correlation and risk analysis.
- AI-powered root cause analysis.
- Automated code-level remediation suggestions.
- Agentic security investigation workflows.
- Interactive security dashboard.

**Build securely. Detect early. Fix confidently.**