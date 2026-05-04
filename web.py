#!/usr/bin/env python3
"""
VulnParser - Automated Web Vulnerability Scanner
Major Project | Cybersecurity 
"""

import os
import subprocess
import sys
import re
import json
import time
import shlex
import datetime
import urllib.parse
import urllib.request
import threading
from pathlib import Path

# ─────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────

def run(cmd_list, timeout=30):
    """Safe subprocess runner — no shell=True to prevent injection."""
    try:
        result = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return ""
    except Exception as e:
        return f"[ERROR: {e}]"

def tool_available(name):
    """Check if a CLI tool is installed."""
    return bool(run(["which", name]))

def clean_target(target):
    """Strip protocol and trailing slash."""
    return target.replace("https://", "").replace("http://", "").rstrip("/")

def severity_label(score):
    if score >= 8:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score >= 2:
        return "LOW"
    return "INFO"

def log(msg, level="INFO"):
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
              "FAIL": "\033[91m", "BOLD": "\033[1m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"  {c}[{level}]{reset} {msg}")

# ─────────────────────────────────────────────
#  Scan Modules
# ─────────────────────────────────────────────

def scan_ports(target, scan_type):
    """NMAP port scan — scope depends on scan_type."""
    log("Running port scan...", "INFO")
    findings = []

    if not tool_available("nmap"):
        return {"status": "tool_missing", "tool": "nmap", "findings": []}

    if scan_type == "quick":
        ports = "80,443,8080"
        flags = ["-T4"]
    elif scan_type == "full":
        ports = "1-65535"
        flags = ["-T4", "-sV", "--open"]
    else:  # xss / default
        ports = "80,443,8080,8443,3000,8888"
        flags = ["-T3"]

    cmd = ["nmap"] + flags + ["-p", ports, target]
    output = run(cmd, timeout=120)

    raw_ports = re.findall(r"(\d+/tcp\s+open\s+\S+(?:\s+.+)?)", output)
    for p in raw_ports:
        parts = p.strip().split()
        port_num = parts[0]
        service = parts[2] if len(parts) > 2 else "unknown"
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        score = 8 if port_num in ["21/tcp","23/tcp","3306/tcp","27017/tcp"] else 4
        findings.append({
            "port": port_num,
            "service": service,
            "version": version,
            "severity": severity_label(score),
            "score": score
        })

    os_match = re.search(r"OS details:\s*(.+)", output)
    os_info = os_match.group(1) if os_match else "Unknown"

    log(f"Found {len(findings)} open port(s)", "OK" if findings else "WARN")
    return {"status": "ok", "findings": findings, "os": os_info, "raw": output[:500]}


def scan_subdomains(target):
    """Subdomain enumeration using subfinder."""
    log("Enumerating subdomains...", "INFO")

    if not tool_available("subfinder"):
        return {"status": "tool_missing", "tool": "subfinder", "subdomains": []}

    output = run(["subfinder", "-silent", "-d", target], timeout=60)
    subs = sorted(set(line.strip() for line in output.splitlines() if line.strip()))
    log(f"Found {len(subs)} subdomain(s)", "OK" if subs else "WARN")
    return {"status": "ok", "subdomains": subs}


def collect_urls(target):
    """Collect URLs using gau (GetAllUrls)."""
    log("Collecting URLs from gau...", "INFO")

    if not tool_available("gau"):
        return {"status": "tool_missing", "tool": "gau", "urls": []}

    output = run(["gau", target], timeout=90)
    urls = list(set(line.strip() for line in output.splitlines() if line.strip()))
    log(f"Collected {len(urls)} URL(s)", "OK" if urls else "WARN")
    return {"status": "ok", "urls": urls}


def analyze_javascript(urls):
    """Fetch and analyze JS files for dangerous patterns."""
    log("Analyzing JavaScript files...", "INFO")
    js_findings = []
    js_urls = [u for u in urls if u.endswith(".js") and "jquery" not in u.lower() and "min.js" not in u.lower()]

    DANGEROUS_PATTERNS = {
        "eval()":            (r"\beval\s*\(", 9),
        "document.write":    (r"document\.write\s*\(", 7),
        "innerHTML":         (r"\.innerHTML\s*=", 8),
        "outerHTML":         (r"\.outerHTML\s*=", 8),
        "location.href":     (r"location\.href\s*=", 6),
        "window.location":   (r"window\.location\s*=", 6),
        "setTimeout(str)":   (r"setTimeout\s*\(\s*['\"]", 7),
        "setInterval(str)":  (r"setInterval\s*\(\s*['\"]", 7),
        "postMessage":       (r"\.postMessage\s*\(", 5),
        "srcdoc":            (r"\.srcdoc\s*=", 8),
    }

    for js_url in js_urls[:15]:
        try:
            req = urllib.request.Request(js_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read().decode("utf-8", errors="ignore")

            hits = []
            for name, (pattern, score) in DANGEROUS_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    hits.append({"pattern": name, "count": len(matches), "score": score,
                                 "severity": severity_label(score)})

            if hits:
                hits.sort(key=lambda x: x["score"], reverse=True)
                js_findings.append({"url": js_url, "patterns": hits,
                                    "top_severity": hits[0]["severity"]})
                log(f"  ⚠ Dangerous pattern in {js_url.split('/')[-1]}", "WARN")
        except Exception:
            pass

    log(f"JS analysis done — {len(js_findings)} risky file(s) found",
        "WARN" if js_findings else "OK")
    return js_findings


def test_xss_payloads(urls, payload_file):
    """Fire XSS payloads against discovered URLs and record reflections."""
    log("Testing XSS payloads...", "INFO")
    results = []

    if not os.path.exists(payload_file):
        log("Payload file not found", "WARN")
        return results

    with open(payload_file) as f:
        raw_payloads = [line.strip() for line in f if line.strip() and line.startswith("http")]

    # Pick URLs with query params
    testable = [u for u in urls if "?" in u][:10]
    if not testable and raw_payloads:
        testable = raw_payloads[:10]

    REFLECTION_MARKERS = ["<script", "alert(", "onerror=", "onload=", "<img", "<svg"]

    for url in testable[:10]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read().decode("utf-8", errors="ignore").lower()

            reflected = [m for m in REFLECTION_MARKERS if m.lower() in body]
            if reflected:
                results.append({
                    "url": url,
                    "reflected_markers": reflected,
                    "severity": "HIGH",
                    "score": 8
                })
                log(f"  ⚠ XSS reflection detected: {url[:60]}...", "WARN")
        except Exception:
            pass

    log(f"XSS payload test done — {len(results)} potential reflection(s)", 
        "WARN" if results else "OK")
    return results


def run_xsstrike(target_url, xsstrike_path):
    """Call XSStrike and capture output."""
    log("Running XSStrike deep scan...", "INFO")
    xsstrike_main = os.path.join(xsstrike_path, "xsstrike.py")

    if not os.path.exists(xsstrike_main):
        log("XSStrike not found", "WARN")
        return {"status": "not_found", "output": ""}

    output = run(
        ["python3", xsstrike_main, "--url", target_url, "--crawl", "--skip-dom"],
        timeout=120
    )

    # Parse XSStrike output for findings
    findings = []
    vuln_lines = re.findall(r"(Payload|XSS|Vulnerable|Filtered|WAF).+", output, re.IGNORECASE)
    for line in vuln_lines:
        findings.append(line.strip())

    waf = re.search(r"WAF:\s*(.+)", output)
    waf_name = waf.group(1).strip() if waf else "None detected"

    log(f"XSStrike done — {len(findings)} finding(s), WAF: {waf_name}", 
        "WARN" if findings else "OK")
    return {
        "status": "ok",
        "findings": findings,
        "waf": waf_name,
        "raw": output[:1000]
    }


def check_security_headers(target):
    """Check for missing security headers."""
    log("Checking security headers...", "INFO")
    url = f"https://{target}" if not target.startswith("http") else target

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("HSTS missing — MITM risk", 7),
        "Content-Security-Policy": ("CSP missing — XSS risk elevated", 8),
        "X-Frame-Options": ("Clickjacking possible", 6),
        "X-Content-Type-Options": ("MIME sniffing allowed", 4),
        "Referrer-Policy": ("Referrer leaking", 3),
        "Permissions-Policy": ("Browser features unrestricted", 3),
    }

    missing = []
    present = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, (msg, score) in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                missing.append({"header": header, "issue": msg,
                                "severity": severity_label(score), "score": score})
            else:
                present.append(header)
    except Exception as e:
        log(f"Header check failed: {e}", "WARN")
        return {"status": "error", "missing": [], "present": []}

    log(f"{len(missing)} missing header(s)", "WARN" if missing else "OK")
    return {"status": "ok", "missing": missing, "present": present}


# ─────────────────────────────────────────────
#  Report Generation
# ─────────────────────────────────────────────

def calculate_risk_score(results):
    """Overall risk score 0-10."""
    scores = []
    for port in results.get("ports", {}).get("findings", []):
        scores.append(port["score"])
    for js in results.get("js_analysis", []):
        for p in js["patterns"]:
            scores.append(p["score"])
    for x in results.get("xss_payloads", []):
        scores.append(x["score"])
    for h in results.get("headers", {}).get("missing", []):
        scores.append(h["score"])
    if not scores:
        return 0
    return round(min(10, sum(scores) / max(len(scores), 1) * 1.5), 1)


def generate_html_report(target, scan_type, results, output_dir):
    """Generate a rich HTML dashboard report."""
    score = calculate_risk_score(results)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    score_color = "#ff4444" if score >= 7 else "#ff8800" if score >= 4 else "#00cc88"
    score_label = severity_label(score * 1.1)

    def badge(sev):
        colors = {
            "CRITICAL": "#ff1744", "HIGH": "#ff5722",
            "MEDIUM": "#ff9800", "LOW": "#8bc34a", "INFO": "#607d8b"
        }
        c = colors.get(sev, "#607d8b")
        return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;">{sev}</span>'

    # ── Ports section
    ports_html = ""
    port_findings = results.get("ports", {}).get("findings", [])
    if results.get("ports", {}).get("status") == "tool_missing":
        ports_html = '<p class="tool-missing">⚠ nmap not installed</p>'
    elif port_findings:
        rows = ""
        for p in port_findings:
            rows += f"""<tr>
                <td>{p['port']}</td><td>{p['service']}</td>
                <td>{p.get('version','—')}</td><td>{badge(p['severity'])}</td>
            </tr>"""
        ports_html = f"""<table><thead><tr>
            <th>Port</th><th>Service</th><th>Version</th><th>Severity</th>
        </tr></thead><tbody>{rows}</tbody></table>"""
    else:
        ports_html = '<p class="ok">✓ No risky open ports detected</p>'

    # ── Subdomains
    subs = results.get("subdomains", {}).get("subdomains", [])
    if results.get("subdomains", {}).get("status") == "tool_missing":
        subs_html = '<p class="tool-missing">⚠ subfinder not installed</p>'
    elif subs:
        items = "".join(f'<li>{s}</li>' for s in subs[:20])
        more = f'<li>... and {len(subs)-20} more</li>' if len(subs) > 20 else ""
        subs_html = f'<ul class="subdomain-list">{items}{more}</ul>'
    else:
        subs_html = '<p class="ok">✓ No subdomains found</p>'

    # ── URLs
    urls = results.get("urls", {}).get("urls", [])
    url_count = len(urls)
    urls_html = f'<div class="stat-chip">{url_count} URLs collected</div>'
    if urls:
        sample = "".join(f'<li class="url-item">{u[:90]}{"..." if len(u)>90 else ""}</li>'
                         for u in sorted(urls)[:15])
        urls_html += f'<ul class="url-list">{sample}</ul>'

    # ── JS Analysis
    js_data = results.get("js_analysis", [])
    if js_data:
        js_rows = ""
        for f in js_data:
            patterns = ", ".join(p["pattern"] for p in f["patterns"])
            js_rows += f"""<tr>
                <td class="url-cell">{f['url'].split('/')[-1]}</td>
                <td>{patterns}</td>
                <td>{badge(f['top_severity'])}</td>
            </tr>"""
        js_html = f"""<table><thead><tr>
            <th>File</th><th>Patterns Found</th><th>Severity</th>
        </tr></thead><tbody>{js_rows}</tbody></table>"""
    else:
        js_html = '<p class="ok">✓ No dangerous JS patterns detected</p>'

    # ── XSS Payloads
    xss_data = results.get("xss_payloads", [])
    if xss_data:
        xss_rows = ""
        for x in xss_data:
            markers = ", ".join(x["reflected_markers"])
            xss_rows += f"""<tr>
                <td class="url-cell">{x['url'][:70]}...</td>
                <td>{markers}</td>
                <td>{badge(x['severity'])}</td>
            </tr>"""
        xss_html = f"""<table><thead><tr>
            <th>URL</th><th>Reflected Markers</th><th>Severity</th>
        </tr></thead><tbody>{xss_rows}</tbody></table>"""
    else:
        xss_html = '<p class="ok">✓ No XSS reflections detected</p>'

    # ── Headers
    hdr = results.get("headers", {})
    missing_hdrs = hdr.get("missing", [])
    present_hdrs = hdr.get("present", [])
    if hdr.get("status") == "error":
        hdr_html = '<p class="tool-missing">⚠ Could not fetch headers</p>'
    elif missing_hdrs:
        rows = "".join(f"""<tr>
            <td>{h['header']}</td><td>{h['issue']}</td><td>{badge(h['severity'])}</td>
        </tr>""" for h in missing_hdrs)
        hdr_html = f"""<table><thead><tr>
            <th>Header</th><th>Issue</th><th>Risk</th>
        </tr></thead><tbody>{rows}</tbody></table>"""
        if present_hdrs:
            hdr_html += f'<p style="margin-top:8px;color:#aaa;font-size:12px;">✓ Present: {", ".join(present_hdrs)}</p>'
    else:
        hdr_html = '<p class="ok">✓ All security headers present</p>'

    # ── XSStrike
    xst = results.get("xsstrike", {})
    if xst.get("status") == "not_found":
        xst_html = '<p class="tool-missing">⚠ XSStrike not found in project directory</p>'
    elif xst.get("findings"):
        items = "".join(f"<li>{f}</li>" for f in xst["findings"][:10])
        xst_html = f'<div>WAF: <strong>{xst.get("waf","—")}</strong></div><ul>{items}</ul>'
    else:
        xst_html = f'<p class="ok">✓ No XSS found by XSStrike. WAF: {xst.get("waf","—")}</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnParser — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');

  :root {{
    --bg: #0a0c0f;
    --surface: #111318;
    --surface2: #1a1d24;
    --border: #22262f;
    --accent: #00e5ff;
    --accent2: #ff1744;
    --accent3: #76ff03;
    --text: #e8eaf0;
    --muted: #6b7280;
    --score-color: {score_color};
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }}

  /* Grid background */
  body::before {{
    content: '';
    position: fixed; inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }}

  .page-wrap {{ position: relative; z-index: 1; }}

  /* ── Header ── */
  header {{
    padding: 32px 48px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: linear-gradient(180deg, rgba(0,229,255,0.04) 0%, transparent 100%);
  }}

  .logo {{
    font-size: 13px; font-weight: 700; letter-spacing: 4px;
    color: var(--accent); text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
  }}

  .logo span {{ color: var(--muted); }}

  .header-meta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--muted);
    text-align: right; line-height: 1.8;
  }}

  /* ── Hero ── */
  .hero {{
    padding: 60px 48px 40px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 40px;
    align-items: center;
    border-bottom: 1px solid var(--border);
  }}

  .hero-title {{
    font-size: 13px; font-weight: 600; letter-spacing: 3px;
    color: var(--muted); text-transform: uppercase; margin-bottom: 12px;
    font-family: 'JetBrains Mono', monospace;
  }}

  .target-name {{
    font-size: clamp(28px, 4vw, 48px);
    font-weight: 800;
    color: var(--text);
    word-break: break-all;
    line-height: 1.1;
  }}

  .target-name .accent {{ color: var(--accent); }}

  .scan-pill {{
    margin-top: 16px;
    display: inline-block;
    padding: 4px 14px;
    border: 1px solid var(--accent);
    border-radius: 20px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--accent);
    text-transform: uppercase; letter-spacing: 2px;
  }}

  /* Score ring */
  .score-ring {{
    position: relative;
    width: 160px; height: 160px;
    flex-shrink: 0;
  }}

  .score-ring svg {{ transform: rotate(-90deg); }}

  .score-ring circle {{
    fill: none;
    stroke-width: 8;
    stroke-linecap: round;
  }}

  .ring-bg {{ stroke: var(--border); }}
  .ring-fill {{
    stroke: var(--score-color);
    stroke-dasharray: 408;
    stroke-dashoffset: {408 - (408 * score / 10):.0f};
    filter: drop-shadow(0 0 8px var(--score-color));
    transition: stroke-dashoffset 1s ease;
  }}

  .score-center {{
    position: absolute; inset: 0;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }}

  .score-num {{
    font-size: 36px; font-weight: 800;
    color: var(--score-color);
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
  }}

  .score-lbl {{
    font-size: 10px; font-weight: 700;
    color: var(--score-color); letter-spacing: 2px;
    text-transform: uppercase; opacity: 0.8;
  }}

  /* ── Stats Bar ── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    border-bottom: 1px solid var(--border);
  }}

  .stat {{
    padding: 28px 32px;
    border-right: 1px solid var(--border);
  }}

  .stat:last-child {{ border-right: none; }}

  .stat-label {{
    font-size: 10px; font-weight: 700; letter-spacing: 3px;
    color: var(--muted); text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace; margin-bottom: 8px;
  }}

  .stat-value {{
    font-size: 32px; font-weight: 800;
    color: var(--text); line-height: 1;
  }}

  .stat-value.warn {{ color: var(--accent2); }}
  .stat-value.ok   {{ color: var(--accent3); }}

  /* ── Sections ── */
  .sections {{ padding: 0 48px 48px; }}

  .section {{
    margin-top: 40px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
  }}

  .section-header {{
    padding: 16px 24px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px;
  }}

  .section-icon {{
    width: 28px; height: 28px;
    background: rgba(0,229,255,0.1);
    border: 1px solid rgba(0,229,255,0.2);
    border-radius: 4px;
    display: flex; align-items: center; justify-content: center;
    font-size: 14px;
  }}

  .section-title {{
    font-size: 13px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 2px;
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
  }}

  .section-body {{ padding: 20px 24px; }}

  /* ── Tables ── */
  table {{
    width: 100%; border-collapse: collapse;
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
  }}

  th {{
    text-align: left; padding: 8px 12px;
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--muted); border-bottom: 1px solid var(--border);
    font-weight: 600;
  }}

  td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(34,38,47,0.6);
    vertical-align: top; color: var(--text);
  }}

  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}

  .url-cell {{ max-width: 300px; word-break: break-all; font-size: 11px; color: var(--muted); }}

  /* ── Lists ── */
  .subdomain-list, .url-list {{
    list-style: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }}

  .subdomain-list li {{ padding: 5px 0; color: var(--accent); border-bottom: 1px solid var(--border); }}
  .subdomain-list li::before {{ content: "↪ "; color: var(--muted); }}

  .url-list {{ margin-top: 12px; }}
  .url-item {{
    padding: 4px 8px; color: var(--muted); font-size: 11px;
    border-left: 2px solid var(--border); margin-bottom: 2px;
  }}

  .stat-chip {{
    display: inline-block;
    padding: 4px 12px;
    background: rgba(0,229,255,0.07);
    border: 1px solid rgba(0,229,255,0.15);
    border-radius: 3px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px; color: var(--accent);
    margin-bottom: 12px;
  }}

  .ok {{ color: var(--accent3); font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
  .tool-missing {{ color: var(--accent2); font-family: 'JetBrains Mono', monospace; font-size: 12px; }}

  /* ── Footer ── */
  footer {{
    padding: 24px 48px;
    border-top: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--muted);
    display: flex; justify-content: space-between;
  }}

  /* ── Responsive ── */
  @media (max-width: 768px) {{
    header, .hero, .sections {{ padding-left: 20px; padding-right: 20px; }}
    .hero {{ grid-template-columns: 1fr; }}
    .stats-bar {{ grid-template-columns: 1fr 1fr; }}
    .stat:nth-child(2) {{ border-right: none; }}
    footer {{ flex-direction: column; gap: 8px; }}
  }}
</style>
</head>
<body>
<div class="page-wrap">

<header>
  <div class="logo">Vuln<span>Parser</span> // Scan Report</div>
  <div class="header-meta">
    <div>Generated: {timestamp}</div>
    <div>Scan Type: {scan_type.upper()}</div>
    <div>Engine: VulnParser v2.0</div>
  </div>
</header>

<section class="hero">
  <div>
    <div class="hero-title">// Target Analysis</div>
    <div class="target-name">
      <span class="accent">//</span> {target}
    </div>
    <span class="scan-pill">{scan_type} scan</span>
  </div>

  <div class="score-ring">
    <svg viewBox="0 0 140 140" width="160" height="160">
      <circle class="ring-bg" cx="70" cy="70" r="65"/>
      <circle class="ring-fill" cx="70" cy="70" r="65"/>
    </svg>
    <div class="score-center">
      <div class="score-num">{score}</div>
      <div class="score-lbl">{score_label}</div>
    </div>
  </div>
</section>

<div class="stats-bar">
  <div class="stat">
    <div class="stat-label">Open Ports</div>
    <div class="stat-value {'warn' if port_findings else 'ok'}">{len(port_findings)}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Subdomains</div>
    <div class="stat-value">{len(subs)}</div>
  </div>
  <div class="stat">
    <div class="stat-label">URLs Found</div>
    <div class="stat-value">{url_count}</div>
  </div>
  <div class="stat">
    <div class="stat-label">Missing Headers</div>
    <div class="stat-value {'warn' if missing_hdrs else 'ok'}">{len(missing_hdrs)}</div>
  </div>
</div>

<div class="sections">

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🔍</div>
      <div class="section-title">Port Scan</div>
    </div>
    <div class="section-body">{ports_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🌐</div>
      <div class="section-title">Subdomain Enumeration</div>
    </div>
    <div class="section-body">{subs_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🔗</div>
      <div class="section-title">URL Collection</div>
    </div>
    <div class="section-body">{urls_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">⚡</div>
      <div class="section-title">JavaScript Analysis</div>
    </div>
    <div class="section-body">{js_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">💉</div>
      <div class="section-title">XSS Payload Testing</div>
    </div>
    <div class="section-body">{xss_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">🛡</div>
      <div class="section-title">Security Headers</div>
    </div>
    <div class="section-body">{hdr_html}</div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-icon">⚔</div>
      <div class="section-title">XSStrike Deep Scan</div>
    </div>
    <div class="section-body">{xst_html}</div>
  </div>

</div>

<footer>
  <span>VulnParser v2.0 — For authorized security testing only</span>
  <span>Target: {target} | {timestamp}</span>
</footer>

</div>
</body>
</html>"""

    report_path = os.path.join(output_dir, f"{target}_report.html")
    with open(report_path, "w") as f:
        f.write(html)
    return report_path


def generate_json_report(target, scan_type, results, output_dir):
    """Machine-readable JSON report."""
    report = {
        "meta": {
            "tool": "VulnParser v2.0",
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.datetime.now().isoformat(),
        },
        "risk_score": calculate_risk_score(results),
        "results": results
    }
    path = os.path.join(output_dir, f"{target}_report.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

SCAN_TYPES = ("quick", "full", "xss")

def main():
    print("\n\033[1m\033[94m" + "=" * 55)
    print("  VulnParser v2.0 — Automated Vulnerability Scanner")
    print("=" * 55 + "\033[0m\n")

    if len(sys.argv) < 3:
        print("Usage: python web.py <target> <scan_type>")
        print("       scan_type: quick | full | xss\n")
        print("Example: python web.py demo.testfire.net full\n")
        sys.exit(0)

    target = sys.argv[1]
    scan_type = sys.argv[2].lower()

    if scan_type not in SCAN_TYPES:
        print(f"[!] Invalid scan type '{scan_type}'. Choose from: {', '.join(SCAN_TYPES)}")
        sys.exit(1)

    clean = clean_target(target)
    log(f"Target  : {clean}", "BOLD")
    log(f"Mode    : {scan_type.upper()}", "BOLD")
    print()

    base_path = Path(__file__).parent.resolve()
    output_dir = base_path / clean
    output_dir.mkdir(parents=True, exist_ok=True)

    payload_file = str(base_path / "fast_xssvul.txt")
    xsstrike_path = str(base_path / "XSStrike")

    results = {}
    start = time.time()

    # Always run
    results["ports"]   = scan_ports(clean, scan_type)
    results["headers"] = check_security_headers(clean)
    results["subdomains"] = scan_subdomains(clean)

    # URL collection + dependent modules
    url_result = collect_urls(clean)
    results["urls"] = url_result
    urls = url_result.get("urls", [])

    if scan_type in ("full", "xss"):
        results["js_analysis"]  = analyze_javascript(urls)
        results["xss_payloads"] = test_xss_payloads(urls, payload_file)
        results["xsstrike"]     = run_xsstrike(f"https://{clean}", xsstrike_path)
    else:
        results["js_analysis"]  = []
        results["xss_payloads"] = []
        results["xsstrike"]     = {"status": "skipped"}

    elapsed = round(time.time() - start, 1)
    risk = calculate_risk_score(results)

    print(f"\n\033[1m{'─'*55}")
    print(f"  Scan complete in {elapsed}s")
    print(f"  Overall Risk Score: {risk}/10 ({severity_label(risk * 1.1)})")
    print(f"{'─'*55}\033[0m\n")

    html_path = generate_html_report(clean, scan_type, results, str(output_dir))
    json_path  = generate_json_report(clean, scan_type, results, str(output_dir))

    log(f"HTML Report : {html_path}", "OK")
    log(f"JSON Report : {json_path}", "OK")
    print()

if __name__ == "__main__":
    main()
