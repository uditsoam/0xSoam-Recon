#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — CVE Auto Lookup Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/VoidRecon
#   Usage   : python3 cve_lookup.py -u target.com
#             python3 cve_lookup.py -u target.com --severity CRITICAL
#             python3 cve_lookup.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse, requests, time, yaml
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[91m
  ██████╗██╗   ██╗███████╗    ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗
 ██╔════╝██║   ██║██╔════╝    ██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗
 ██║     ██║   ██║█████╗      ██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝
 ██║     ╚██╗ ██╔╝██╔══╝      ██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝
 ╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║
  ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝
\033[0m
\033[97m  [ Module 15 ] CVE Auto Lookup — NVD API v2\033[0m
\033[93m  Author: Udit Soam | VoidRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_cve(msg):     print(f"{Fore.RED}  [CVE] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Severity colors ──────────────────────────────────────────
SEVERITY_COLOR = {
    "CRITICAL": Fore.RED,
    "HIGH"    : Fore.RED,
    "MEDIUM"  : Fore.YELLOW,
    "LOW"     : Fore.GREEN,
    "NONE"    : Fore.WHITE
}

# ── Common service keyword mappings ─────────────────────────
SERVICE_KEYWORDS = {
    "apache"      : "Apache HTTP Server",
    "nginx"       : "nginx",
    "openssh"     : "OpenSSH",
    "ssh"         : "OpenSSH",
    "openssl"     : "OpenSSL",
    "mysql"       : "MySQL",
    "mariadb"     : "MariaDB",
    "postgresql"  : "PostgreSQL",
    "redis"       : "Redis",
    "mongodb"     : "MongoDB",
    "iis"         : "Microsoft IIS",
    "tomcat"      : "Apache Tomcat",
    "php"         : "PHP",
    "wordpress"   : "WordPress",
    "drupal"      : "Drupal",
    "joomla"      : "Joomla",
    "vsftpd"      : "vsftpd",
    "proftpd"     : "ProFTPD",
    "samba"       : "Samba",
    "smbd"        : "Samba",
    "exim"        : "Exim",
    "postfix"     : "Postfix",
    "dovecot"     : "Dovecot",
    "bind"        : "ISC BIND",
    "named"       : "ISC BIND",
    "python"      : "Python",
    "ruby"        : "Ruby",
    "node"        : "Node.js",
    "nodejs"      : "Node.js",
    "java"        : "Java",
    "jenkins"     : "Jenkins",
    "elastic"     : "Elasticsearch",
}


def get_args():
    parser = argparse.ArgumentParser(
        prog="cve_lookup.py",
        description="VoidRecon — CVE Auto Lookup via NVD API v2",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 cve_lookup.py -u target.com
  python3 cve_lookup.py -u target.com --severity CRITICAL
  python3 cve_lookup.py -u target.com --severity HIGH
  python3 cve_lookup.py -u target.com --max-cves 5
  python3 cve_lookup.py -u target.com -o /tmp/results
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("-o", "--output",
        default="output/json",
        help="Output directory (default: output/json)"
    )
    parser.add_argument("--severity",
        default="ALL",
        choices=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter CVEs by severity (default: ALL)"
    )
    parser.add_argument("--max-cves",
        type=int, default=5,
        help="Max CVEs per service (default: 5)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def load_api_key():
    try:
        with open("config/config.yaml") as f:
            config = yaml.safe_load(f)
        key = config.get("nvd", {}).get("api_key", "")
        if not key or key == "USER_NVD_KEY":
            return None
        return key
    except Exception as e:
        log_error(f"config.yaml error: {e}")
        return None


def load_port_services(output_dir):
    port_file = os.path.join(output_dir, "port_scanner.json")
    services  = []

    if not os.path.exists(port_file):
        log_warn("port_scanner.json not found — run port_scanner first")
        return services

    try:
        with open(port_file) as f:
            data = json.load(f)

        for port in data.get("open_ports", []):
            service = port.get("service", "")
            version = port.get("version", "")
            if service:
                services.append({
                    "port"   : port.get("port", ""),
                    "service": service,
                    "version": version,
                    "risk"   : port.get("risk", "LOW")
                })

        log_success(f"Loaded {len(services)} services from port_scanner.json")
        return services

    except Exception as e:
        log_error(f"Could not read port_scanner.json: {e}")
        return []


def extract_keyword(service, version):
    combined = f"{service} {version}".lower()
    for keyword, name in SERVICE_KEYWORDS.items():
        if keyword in combined:
            return name, version
    return service, version


def search_nvd(keyword, version, api_key, max_cves=5):
    headers = {"User-Agent": "VoidRecon/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    # Build search query
    query = keyword
    if version:
        # Extract version number only
        ver_parts = version.split()
        for part in ver_parts:
            if any(c.isdigit() for c in part):
                query = f"{keyword} {part}"
                break

    params = {
        "keywordSearch" : query,
        "resultsPerPage": max_cves,
        "startIndex"    : 0
    }

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers = headers,
            params  = params,
            timeout = 20
        )

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:
            log_error("NVD API key invalid")
            return None
        elif resp.status_code == 429:
            log_warn("NVD rate limit — waiting 6 seconds")
            time.sleep(6)
            return search_nvd(keyword, version, api_key, max_cves)
        else:
            log_warn(f"NVD API returned: {resp.status_code}")
            return None

    except requests.exceptions.Timeout:
        log_warn(f"NVD request timed out for: {keyword}")
        return None
    except Exception as e:
        log_error(f"NVD search error: {e}")
        return None


def parse_cve(cve_item):
    try:
        cve_id  = cve_item.get("cve", {}).get("id", "")
        desc    = cve_item.get("cve", {}).get("descriptions", [{}])
        desc_en = next(
            (d["value"] for d in desc if d.get("lang") == "en"),
            "No description"
        )

        # Get CVSS score
        metrics  = cve_item.get("cve", {}).get("metrics", {})
        cvss_v3  = metrics.get("cvssMetricV31", [{}])
        cvss_v2  = metrics.get("cvssMetricV2", [{}])

        if cvss_v3:
            score    = cvss_v3[0].get("cvssData", {}).get("baseScore", 0)
            severity = cvss_v3[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            vector   = cvss_v3[0].get("cvssData", {}).get("vectorString", "")
        elif cvss_v2:
            score    = cvss_v2[0].get("cvssData", {}).get("baseScore", 0)
            severity = cvss_v2[0].get("baseSeverity", "UNKNOWN")
            vector   = cvss_v2[0].get("cvssData", {}).get("vectorString", "")
        else:
            score    = 0
            severity = "UNKNOWN"
            vector   = ""

        published = cve_item.get("cve", {}).get("published", "")[:10]
        modified  = cve_item.get("cve", {}).get("lastModified", "")[:10]

        return {
            "cve_id"     : cve_id,
            "score"      : score,
            "severity"   : severity,
            "vector"     : vector,
            "description": desc_en[:300],
            "published"  : published,
            "modified"   : modified,
            "url"        : f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }

    except Exception as e:
        return {"error": str(e)}


def run(domain, output_dir="output/json",
        severity_filter="ALL", max_cves=5):

    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target   : {domain}")
    log_info(f"Severity : {severity_filter}")
    log_info(f"Max CVEs : {max_cves} per service")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    api_key = load_api_key()
    if not api_key:
        log_warn("No NVD API key — using unauthenticated mode")
        log_warn("Rate limit: 5 requests/30 sec without key")
        log_warn("Get free key: nvd.nist.gov/developers/request-an-api-key")
    else:
        log_success("NVD API key loaded")

    # Load services from port scanner
    services = load_port_services(output_dir)

    if not services:
        log_warn("No services found — run port_scanner module first")
        data = {
            "module"      : "cve_lookup",
            "domain"      : domain,
            "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_cves"  : 0,
            "cve_findings": []
        }
        out_path = os.path.join(output_dir, "cve_lookup.json")
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return data

    all_findings    = []
    critical_count  = 0
    high_count      = 0

    for svc in services:
        port    = svc.get("port", "")
        service = svc.get("service", "")
        version = svc.get("version", "")
        risk    = svc.get("risk", "")

        keyword, ver = extract_keyword(service, version)

        log_info(
            f"Searching CVEs for: {keyword} {ver} "
            f"(port {port})"
        )

        nvd_result = search_nvd(keyword, ver, api_key, max_cves)

        if nvd_result is None:
            log_error("NVD API failed — stopping CVE lookup")
            break

        cves = nvd_result.get("vulnerabilities", [])

        for cve_item in cves:
            parsed = parse_cve(cve_item)
            sev    = parsed.get("severity", "UNKNOWN")
            score  = parsed.get("score", 0)

            # Apply severity filter
            if severity_filter != "ALL":
                if sev != severity_filter:
                    continue

            finding = {
                "port"       : port,
                "service"    : service,
                "version"    : version,
                "keyword"    : keyword,
                **parsed
            }
            all_findings.append(finding)

            # Color by severity
            color = SEVERITY_COLOR.get(sev, Fore.WHITE)

            log_cve(
                f"{color}[{sev}]{Style.RESET_ALL} "
                f"{parsed['cve_id']} | "
                f"Score: {score} | "
                f"Port: {port}/{service}"
            )
            log_data(f"{parsed['description'][:100]}...")

            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1

        # Rate limit
        wait = 1.5 if api_key else 7
        time.sleep(wait)

    # Sort by score descending
    all_findings.sort(
        key=lambda x: x.get("score", 0),
        reverse=True
    )

    data = {
        "module"       : "cve_lookup",
        "domain"       : domain,
        "timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity_filter": severity_filter,
        "total_cves"   : len(all_findings),
        "critical"     : critical_count,
        "high"         : high_count,
        "cve_findings" : all_findings
    }

    out_path = os.path.join(output_dir, "cve_lookup.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"CVE Lookup Complete")
    log_success(f"Total CVEs found : {len(all_findings)}")
    if critical_count:
        log_cve(f"CRITICAL         : {critical_count}")
    if high_count:
        log_warn(f"HIGH             : {high_count}")
    log_success(f"Saved → {out_path}")
    print(f"\033[97m{'═'*60}\033[0m\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner:
        banner()
    run(
        domain          = args.url,
        output_dir      = args.output,
        severity_filter = args.severity,
        max_cves        = args.max_cves
    )
