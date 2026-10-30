"""
Reads local package manifests (package.json for Next.js, *.csproj for .NET)
and flags dependencies you should manually check against the NVD / GitHub
Advisory Database. This does NOT call any external CVE API by default
(keeps it offline-friendly) -- it just extracts versions so you (or the AI
layer) can check them.
"""
import json
import os
import re
import subprocess


def read_package_json(path="package.json"):
    deps = {}
    if not os.path.exists(path):
        return deps
    with open(path) as f:
        data = json.load(f)
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))
    return deps


def read_csproj(path):
    """path can be a single .csproj file or a directory to search."""
    deps = {}
    files = []
    if os.path.isdir(path):
        for root, _, names in os.walk(path):
            files.extend(os.path.join(root, n) for n in names if n.endswith(".csproj"))
    elif os.path.exists(path):
        files = [path]

    pattern = re.compile(r'<PackageReference Include="([^"]+)" Version="([^"]+)"')
    for fpath in files:
        with open(fpath) as f:
            content = f.read()
        for name, version in pattern.findall(content):
            deps[name] = version
    return deps


def summarize(deps, ecosystem):
    findings = []
    if not deps:
        findings.append({"severity": "info", "title": f"No {ecosystem} dependencies found", "detail": ""})
        return findings

    findings.append({
        "severity": "info",
        "title": f"{len(deps)} {ecosystem} dependencies found -- cross-check versions manually",
        "detail": ", ".join(f"{n}@{v}" for n, v in list(deps.items())[:15]) + (" ..." if len(deps) > 15 else ""),
        "fix": f"Run `npm audit` (Node) or `dotnet list package --vulnerable` (.NET) "
               f"for an authoritative CVE check against these {ecosystem} packages.",
    })
    return findings


def run_npm_audit(project_dir, timeout=60):
    """
    Runs the real `npm audit --json` against your Next.js project and parses
    actual known CVEs (this is the authoritative check -- not guesswork).
    Requires Node/npm installed and a node_modules or lockfile present.
    """
    findings = []
    if not os.path.isfile(os.path.join(project_dir, "package.json")):
        return [{"severity": "info", "title": "No package.json found for npm audit", "detail": project_dir}]

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=project_dir, capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(result.stdout or "{}")
    except FileNotFoundError:
        return [{"severity": "info", "title": "npm not found on PATH", "detail": "Install Node.js to enable real CVE scanning."}]
    except subprocess.TimeoutExpired:
        return [{"severity": "info", "title": "npm audit timed out", "detail": f"Exceeded {timeout}s"}]
    except json.JSONDecodeError:
        return [{"severity": "info", "title": "Could not parse npm audit output", "detail": ""}]

    vulns = data.get("vulnerabilities", {})
    if not vulns:
        findings.append({"severity": "ok", "title": "npm audit: no known vulnerabilities", "detail": ""})
        return findings

    sev_map = {"critical": "high", "high": "high", "moderate": "medium", "low": "low", "info": "info"}
    for pkg_name, info in vulns.items():
        npm_sev = info.get("severity", "info")
        via = info.get("via", [])
        cve_names = [v.get("title", str(v)) if isinstance(v, dict) else str(v) for v in via]
        findings.append({
            "severity": sev_map.get(npm_sev, "medium"),
            "title": f"Known vulnerability in '{pkg_name}' ({npm_sev})",
            "detail": "; ".join(cve_names[:3]),
            "fix": f"Run `npm audit fix` in {project_dir}, or manually update '{pkg_name}' to a patched version.",
        })
    return findings


def run_dotnet_vulnerable_check(project_dir, timeout=60):
    """
    Runs the real `dotnet list package --vulnerable --include-transitive`
    against your .NET project -- authoritative CVE check via NuGet's
    vulnerability database.
    """
    findings = []
    try:
        result = subprocess.run(
            ["dotnet", "list", project_dir, "package", "--vulnerable", "--include-transitive"],
            capture_output=True, text=True, timeout=timeout,
        )
        output = result.stdout
    except FileNotFoundError:
        return [{"severity": "info", "title": "dotnet CLI not found on PATH", "detail": "Install .NET SDK to enable real CVE scanning."}]
    except subprocess.TimeoutExpired:
        return [{"severity": "info", "title": "dotnet list package timed out", "detail": f"Exceeded {timeout}s"}]

    if "has the following vulnerable packages" not in output:
        findings.append({"severity": "ok", "title": "dotnet: no known vulnerable packages", "detail": ""})
        return findings

    # Parse lines like: "   > Newtonsoft.Json   12.0.1   High   https://..."
    sev_map = {"critical": "high", "high": "high", "moderate": "medium", "low": "low"}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(">"):
            parts = line.lstrip(">").split()
            if len(parts) >= 3:
                pkg_name, version = parts[0], parts[1]
                sev_word = parts[2].lower()
                advisory_url = parts[-1] if parts[-1].startswith("http") else ""
                findings.append({
                    "severity": sev_map.get(sev_word, "medium"),
                    "title": f"Known vulnerability in '{pkg_name}' {version} ({sev_word})",
                    "detail": advisory_url,
                    "fix": f"Run `dotnet add package {pkg_name}` with a patched version in {project_dir}.",
                })
    if not findings:
        findings.append({"severity": "info", "title": "dotnet reported vulnerabilities but output format was unexpected", "detail": output[:300]})
    return findings
