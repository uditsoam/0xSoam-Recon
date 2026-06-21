#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — JSON Aggregator + Risk Engine
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
# ═══════════════════════════════════════════════════════════

import json, os, sys
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")


def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception as e:
        log_warn(f"Could not read {filepath}: {e}")
        return {}


def aggregate(json_dir="output/json", domain="unknown"):
    log_info(f"Aggregating results from: {json_dir}")
    print(f"{Fore.WHITE}  {'─'*55}{Style.RESET_ALL}")

    # ── Load all module outputs ──────────────────────────────
    subdomain  = load_json(f"{json_dir}/subdomain_enum.json")
    osint      = load_json(f"{json_dir}/osint_harvest.json")
    shodan     = load_json(f"{json_dir}/shodan_lookup.json")
    dns        = load_json(f"{json_dir}/dns_whois.json")
    ssl        = load_json(f"{json_dir}/ssl_checker.json")
    ports      = load_json(f"{json_dir}/port_scanner.json")
    crawler    = load_json(f"{json_dir}/web_crawler.json")
    headers    = load_json(f"{json_dir}/http_headers.json")
    screenshot = load_json(f"{json_dir}/screenshot.json")
    tech       = load_json(f"{json_dir}/tech_stack.json")
    takeover   = load_json(f"{json_dir}/takeover_check.json")
    github     = load_json(f"{json_dir}/github_dork.json")
    wayback    = load_json(f"{json_dir}/wayback.json")
    breach     = load_json(f"{json_dir}/email_breach.json")
    cve        = load_json(f"{json_dir}/cve_lookup.json")
    dorks      = load_json(f"{json_dir}/dork_generator.json")

    # ── Extract key counts ───────────────────────────────────
    total_subdomains = len(subdomain.get("subdomains", []))
    total_emails     = osint.get("total_emails", 0)
    total_ports      = ports.get("total_open", 0)
    high_ports       = ports.get("risk_summary", {}).get("high", 0)
    total_paths      = crawler.get("total_found", 0)
    juicy_paths      = crawler.get("juicy_paths", 0)
    total_certs      = ssl.get("total_certs", 0)
    total_shodan     = shodan.get("total", 0)
    security_grade   = headers.get("security_grade", "N/A")
    cve_list         = shodan.get("cve_summary", [])
    missing_headers  = len(
        headers.get("header_analysis", {})
               .get("missing_security", [])
    )
    takeover_count   = takeover.get("total_vulnerable", 0)
    breach_count     = breach.get("total_breached", 0)
    cve_findings     = cve.get("cve_findings", [])
    github_findings  = github.get("findings", [])
    wayback_juicy    = wayback.get("interesting_count", 0)

    # ── Print summary ────────────────────────────────────────
    log_success(f"Subdomains        : {total_subdomains}")
    log_success(f"Emails            : {total_emails}")
    log_success(f"Open ports        : {total_ports} ({high_ports} HIGH)")
    log_success(f"Web paths         : {total_paths} ({juicy_paths} juicy)")
    log_success(f"SSL certs         : {total_certs}")
    log_success(f"Shodan results    : {total_shodan}")
    log_success(f"Security grade    : {security_grade}")
    log_success(f"Missing headers   : {missing_headers}")
    log_success(f"Takeover vulns    : {takeover_count}")
    log_success(f"Breached emails   : {breach_count}")
    log_success(f"CVE findings      : {len(cve_findings)}")
    log_success(f"GitHub secrets    : {len(github_findings)}")
    log_success(f"Wayback juicy     : {wayback_juicy}")

    if cve_list:
        log_warn(f"Shodan CVEs       : {cve_list}")

    # ── Build pre-risk merged object ─────────────────────────
    merged = {
        "meta": {
            "tool"     : "0xSoamRecon",
            "version"  : "2.0",
            "author"   : "Udit Soam",
            "domain"   : domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "github"   : "https://github.com/uditsoam/0xSoamRecon"
        },
        "summary": {
            "total_subdomains"  : total_subdomains,
            "total_emails"      : total_emails,
            "total_open_ports"  : total_ports,
            "high_risk_ports"   : high_ports,
            "total_web_paths"   : total_paths,
            "juicy_paths"       : juicy_paths,
            "total_certs"       : total_certs,
            "shodan_results"    : total_shodan,
            "cves_detected"     : cve_list,
            "security_grade"    : security_grade,
            "missing_headers"   : missing_headers,
            "takeover_vulns"    : takeover_count,
            "breached_emails"   : breach_count,
            "github_secrets"    : len(github_findings),
            "wayback_juicy"     : wayback_juicy
        },
        # Module data
        "subdomains"        : subdomain.get("subdomains", []),
        "emails"            : osint.get("emails", []),
        "hosts"             : osint.get("hosts", []),
        "dns_records"       : dns.get("dns_records", {}),
        "whois"             : dns.get("whois", {}),
        "open_ports"        : ports.get("open_ports", []),
        "web_paths"         : crawler.get("results", []),
        "http_headers"      : headers.get("header_analysis", {}),
        "ssl_certs"         : ssl.get("cert_history", []),
        "live_ssl"          : ssl.get("live_ssl", {}),
        "shodan"            : shodan.get("results", []),
        "screenshots"       : screenshot.get("captured", []),
        "tech_stack"        : tech,
        "takeover_results"  : takeover,
        "github_findings"   : github_findings,
        "wayback"           : wayback,
        "breach_summary"    : breach,
        "cve_findings"      : cve_findings,
        "dorks"             : dorks.get("all_dorks", [])
    }

    # ── Run Risk Engine ───────────────────────────────────────
    try:
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        ))
        from reporter.risk_engine import calculate_risk
        log_info("Running risk engine...")
        risk_result = calculate_risk(merged)

        # Add risk data to summary
        merged["summary"]["risk_score"] = risk_result["risk_score"]
        merged["summary"]["risk_grade"] = risk_result["risk_grade"]
        merged["summary"]["risk_label"] = risk_result["risk_label"]

        # Add to merged
        merged["risk_analysis"] = risk_result

        log_success(
            f"Risk Score: {risk_result['risk_score']}/100 "
            f"— Grade: {risk_result['risk_grade']}"
        )

    except Exception as e:
        log_warn(f"Risk engine error: {e}")
        merged["risk_analysis"] = {}

    # ── Save merged JSON ─────────────────────────────────────
    out_path = os.path.join(json_dir, "recon_report.json")
    with open(out_path, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"{Fore.WHITE}  {'─'*55}{Style.RESET_ALL}")
    log_success(f"Merged report → {out_path}")
    return merged


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    aggregate("output/json", domain)
