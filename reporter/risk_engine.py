#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Risk Engine
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
# ═══════════════════════════════════════════════════════════

from colorama import Fore, Style, init
init(autoreset=True)

def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_crit(msg):    print(f"{Fore.RED}  [!!!] {msg}{Style.RESET_ALL}")

# ── Deduction rules ──────────────────────────────────────────
DEDUCTIONS = {
    "high_risk_port"       : 15,   # per port, max 45
    "missing_sec_header"   : 5,    # per header, max 35
    "cve_found"            : 20,   # per CVE, max 40
    "leaked_credentials"   : 25,   # flat
    "subdomain_takeover"   : 30,   # per subdomain, max 30
    "juicy_path"           : 10,   # per path, max 20
    "github_secret"        : 25,   # flat
    "email_breach"         : 15,   # flat
    "info_disclosure"      : 10,   # server info leaked
    "no_ssl"               : 20,   # no HTTPS
}

# ── Grade thresholds ─────────────────────────────────────────
GRADES = [
    (90, "A", "Low Risk",      Fore.GREEN),
    (75, "B", "Guarded",       Fore.GREEN),
    (60, "C", "Elevated",      Fore.YELLOW),
    (40, "D", "High Risk",     Fore.RED),
    (0,  "F", "Critical Risk", Fore.RED),
]

# ── Recommendation templates ─────────────────────────────────
RECOMMENDATIONS = {
    "port_22"   : {
        "priority" : "HIGH",
        "finding"  : "SSH (Port 22) exposed to internet",
        "impact"   : "Brute force attacks, credential stuffing",
        "fix"      : "Disable password auth, use SSH keys only. "
                     "Restrict access via firewall to known IPs."
    },
    "port_23"   : {
        "priority" : "CRITICAL",
        "finding"  : "Telnet (Port 23) open — unencrypted protocol",
        "impact"   : "All traffic including credentials sent in plaintext",
        "fix"      : "Disable Telnet immediately. Replace with SSH."
    },
    "port_445"  : {
        "priority" : "CRITICAL",
        "finding"  : "SMB (Port 445) exposed",
        "impact"   : "EternalBlue MS17-010, ransomware propagation",
        "fix"      : "Block port 445 at firewall. Apply MS17-010 patch."
    },
    "port_3389" : {
        "priority" : "CRITICAL",
        "finding"  : "RDP (Port 3389) exposed to internet",
        "impact"   : "BlueKeep vulnerability, brute force, ransomware",
        "fix"      : "Restrict RDP to VPN only. Enable NLA. Patch BlueKeep."
    },
    "port_3306" : {
        "priority" : "HIGH",
        "finding"  : "MySQL (Port 3306) exposed to internet",
        "impact"   : "Direct database access, data exfiltration",
        "fix"      : "Bind MySQL to localhost only (127.0.0.1). "
                     "Use firewall to block external access."
    },
    "port_5432" : {
        "priority" : "HIGH",
        "finding"  : "PostgreSQL (Port 5432) exposed",
        "impact"   : "Direct database access, data breach",
        "fix"      : "Restrict to localhost. Use pg_hba.conf to limit access."
    },
    "port_6379" : {
        "priority" : "CRITICAL",
        "finding"  : "Redis (Port 6379) exposed — often unauthenticated",
        "impact"   : "Unauthenticated access, RCE via config write",
        "fix"      : "Bind to localhost. Set requirepass in redis.conf."
    },
    "port_27017": {
        "priority" : "CRITICAL",
        "finding"  : "MongoDB (Port 27017) exposed — often no auth",
        "impact"   : "Unauthenticated database access, data theft",
        "fix"      : "Enable MongoDB authentication. Bind to localhost."
    },
    "hsts"      : {
        "priority" : "HIGH",
        "finding"  : "Missing Strict-Transport-Security header",
        "impact"   : "SSL stripping attacks, MITM vulnerabilities",
        "fix"      : "Add header: Strict-Transport-Security: "
                     "max-age=31536000; includeSubDomains"
    },
    "csp"       : {
        "priority" : "HIGH",
        "finding"  : "Missing Content-Security-Policy header",
        "impact"   : "XSS attacks, data injection, clickjacking",
        "fix"      : "Implement CSP header. Start with: "
                     "Content-Security-Policy: default-src 'self'"
    },
    "xframe"    : {
        "priority" : "MEDIUM",
        "finding"  : "Missing X-Frame-Options header",
        "impact"   : "Clickjacking attacks",
        "fix"      : "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "xcontent"  : {
        "priority" : "MEDIUM",
        "finding"  : "Missing X-Content-Type-Options header",
        "impact"   : "MIME sniffing attacks",
        "fix"      : "Add: X-Content-Type-Options: nosniff"
    },
    "referrer"  : {
        "priority" : "LOW",
        "finding"  : "Missing Referrer-Policy header",
        "impact"   : "Sensitive URL data leakage via Referrer header",
        "fix"      : "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "cve"       : {
        "priority" : "CRITICAL",
        "finding"  : "Known CVE detected on running service",
        "impact"   : "Remote code execution, privilege escalation",
        "fix"      : "Patch affected service to latest version immediately. "
                     "Check vendor security advisories."
    },
    "takeover"  : {
        "priority" : "CRITICAL",
        "finding"  : "Subdomain takeover vulnerability detected",
        "impact"   : "Account takeover, phishing, cookie theft",
        "fix"      : "Remove dangling DNS record or reclaim "
                     "the service immediately."
    },
    "breach"    : {
        "priority" : "HIGH",
        "finding"  : "Employee emails found in breach databases",
        "impact"   : "Credential stuffing, account takeover",
        "fix"      : "Force password reset for breached accounts. "
                     "Enable MFA immediately."
    },
    "github"    : {
        "priority" : "CRITICAL",
        "finding"  : "Secrets/credentials found in GitHub repositories",
        "impact"   : "Immediate unauthorized access to services",
        "fix"      : "Rotate ALL exposed credentials immediately. "
                     "Use git-secrets to prevent future leaks."
    },
    "juicy"     : {
        "priority" : "HIGH",
        "finding"  : "Sensitive paths accessible (admin/backup/config)",
        "impact"   : "Unauthorized access to sensitive functionality",
        "fix"      : "Restrict access via authentication. "
                     "Remove unnecessary exposed paths."
    },
    "info_leak" : {
        "priority" : "MEDIUM",
        "finding"  : "Server information disclosed in HTTP headers",
        "impact"   : "Aids targeted attacks on specific versions",
        "fix"      : "Remove Server and X-Powered-By headers. "
                     "Configure server to hide version info."
    },
}


def calculate_risk(merged_data):
    log_info("Calculating risk score...")

    score        = 100
    deductions   = []
    recommendations = []

    # ── Open ports risk ───────────────────────────────────────
    open_ports = merged_data.get("open_ports", [])
    high_ports = [p for p in open_ports if p.get("risk") == "HIGH"]
    port_deduct = min(len(high_ports) * DEDUCTIONS["high_risk_port"], 45)

    if high_ports:
        score -= port_deduct
        deductions.append({
            "reason" : f"{len(high_ports)} HIGH risk port(s) open",
            "points" : -port_deduct
        })

        for port in high_ports:
            p_num   = port.get("port", 0)
            key     = f"port_{p_num}"
            if key in RECOMMENDATIONS:
                rec = RECOMMENDATIONS[key].copy()
                if rec not in recommendations:
                    recommendations.append(rec)

    # ── Missing security headers ──────────────────────────────
    http_data       = merged_data.get("http_headers", {})
    missing_headers = http_data.get("missing_security", [])
    header_deduct   = min(
        len(missing_headers) * DEDUCTIONS["missing_sec_header"], 35
    )

    if missing_headers:
        score -= header_deduct
        deductions.append({
            "reason" : f"{len(missing_headers)} security header(s) missing",
            "points" : -header_deduct
        })

        header_map = {
            "Strict-Transport-Security" : "hsts",
            "Content-Security-Policy"   : "csp",
            "X-Frame-Options"           : "xframe",
            "X-Content-Type-Options"    : "xcontent",
            "Referrer-Policy"           : "referrer",
        }
        for h in missing_headers:
            h_name = h.get("header", "")
            key    = header_map.get(h_name)
            if key and key in RECOMMENDATIONS:
                rec = RECOMMENDATIONS[key].copy()
                rec["finding"] = f"Missing {h_name} header"
                if rec not in recommendations:
                    recommendations.append(rec)

    # ── CVEs detected ─────────────────────────────────────────
    cves         = merged_data.get("summary", {}).get("cves_detected", [])
    cve_findings = merged_data.get("cve_findings", [])
    cve_count    = max(len(cves), len(cve_findings))
    cve_deduct   = min(cve_count * DEDUCTIONS["cve_found"], 40)

    if cve_count:
        score -= cve_deduct
        deductions.append({
            "reason" : f"{cve_count} CVE(s) detected",
            "points" : -cve_deduct
        })
        rec = RECOMMENDATIONS["cve"].copy()
        if cves:
            rec["finding"] = f"CVEs detected: {', '.join(cves[:3])}"
        if rec not in recommendations:
            recommendations.append(rec)

    # ── Subdomain takeover ────────────────────────────────────
    takeover_data = merged_data.get("takeover_results", {})
    vulnerable    = takeover_data.get("total_vulnerable", 0)

    if vulnerable:
        tak_deduct = min(
            vulnerable * DEDUCTIONS["subdomain_takeover"], 30
        )
        score -= tak_deduct
        deductions.append({
            "reason" : f"{vulnerable} subdomain takeover(s) found",
            "points" : -tak_deduct
        })
        rec = RECOMMENDATIONS["takeover"].copy()
        if rec not in recommendations:
            recommendations.append(rec)

    # ── Juicy paths ───────────────────────────────────────────
    juicy_count  = merged_data.get("summary", {}).get("juicy_paths", 0)
    juicy_deduct = min(
        juicy_count * DEDUCTIONS["juicy_path"], 20
    )

    if juicy_count:
        score -= juicy_deduct
        deductions.append({
            "reason" : f"{juicy_count} juicy/sensitive path(s) found",
            "points" : -juicy_deduct
        })
        rec = RECOMMENDATIONS["juicy"].copy()
        if rec not in recommendations:
            recommendations.append(rec)

    # ── GitHub secrets ────────────────────────────────────────
    github_findings = merged_data.get("github_findings", [])
    if github_findings:
        score -= DEDUCTIONS["github_secret"]
        deductions.append({
            "reason" : f"{len(github_findings)} GitHub secret(s) found",
            "points" : -DEDUCTIONS["github_secret"]
        })
        rec = RECOMMENDATIONS["github"].copy()
        if rec not in recommendations:
            recommendations.append(rec)

    # ── Email breaches ────────────────────────────────────────
    breached = merged_data.get("breach_summary", {}).get(
        "total_breached", 0
    )
    if breached:
        score -= DEDUCTIONS["email_breach"]
        deductions.append({
            "reason" : f"{breached} email(s) found in breach databases",
            "points" : -DEDUCTIONS["email_breach"]
        })
        rec = RECOMMENDATIONS["breach"].copy()
        if rec not in recommendations:
            recommendations.append(rec)

    # ── Info disclosure ───────────────────────────────────────
    info_leaked = http_data.get("info_leaked", {})
    if info_leaked:
        score -= DEDUCTIONS["info_disclosure"]
        deductions.append({
            "reason" : "Server information disclosed in headers",
            "points" : -DEDUCTIONS["info_disclosure"]
        })
        rec = RECOMMENDATIONS["info_leak"].copy()
        if rec not in recommendations:
            recommendations.append(rec)

    # ── Final score ───────────────────────────────────────────
    score = max(0, score)

    # Grade
    grade       = "F"
    grade_label = "Critical Risk"
    for threshold, g, label, color in GRADES:
        if score >= threshold:
            grade       = g
            grade_label = label
            break

    # Sort recommendations by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recommendations.sort(
        key=lambda x: priority_order.get(x.get("priority", "LOW"), 3)
    )

    # Print summary
    print(f"\n  {Fore.WHITE}{'─'*50}{Style.RESET_ALL}")
    log_info(f"Risk Score : {score}/100")
    log_info(f"Risk Grade : {grade} — {grade_label}")

    if deductions:
        log_warn("Deductions:")
        for d in deductions:
            print(
                f"    {Fore.RED}{d['points']:>4}{Style.RESET_ALL}  "
                f"{d['reason']}"
            )

    if recommendations:
        log_warn(f"{len(recommendations)} recommendation(s) generated")

    print(f"  {Fore.WHITE}{'─'*50}{Style.RESET_ALL}\n")

    return {
        "risk_score"      : score,
        "risk_grade"      : grade,
        "risk_label"      : grade_label,
        "deductions"      : deductions,
        "recommendations" : recommendations
    }
