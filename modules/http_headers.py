#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — HTTP Headers Analyzer Module
#   Author  : Udit Soam
#   Usage   : python3 http_headers.py -u target.com
#             python3 http_headers.py -u target.com --https
#             python3 http_headers.py -u target.com --nikto
#             python3 http_headers.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, requests
from datetime import datetime
from colorama import Fore, Style, init
requests.packages.urllib3.disable_warnings()
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
 ██╗  ██╗████████╗████████╗██████╗
 ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗
 ███████║   ██║      ██║   ██████╔╝
 ██╔══██║   ██║      ██║   ██╔═══╝
 ██║  ██║   ██║      ██║   ██║
 ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝   HEADERS
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 08 ] HTTP Headers & Security Misconfiguration Analysis{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | VoidRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_missing(msg): print(f"{Fore.RED}      [MISSING] {msg}{Style.RESET_ALL}")
def log_present(msg): print(f"{Fore.GREEN}      [OK] {msg}{Style.RESET_ALL}")
def log_info2(msg):   print(f"{Fore.BLUE}      [INFO] {msg}{Style.RESET_ALL}")

# Security headers every site should have
SECURITY_HEADERS = {
    "Strict-Transport-Security" : "HSTS missing — site vulnerable to SSL stripping",
    "X-Frame-Options"           : "Clickjacking protection missing",
    "X-Content-Type-Options"    : "MIME sniffing protection missing",
    "Content-Security-Policy"   : "CSP missing — XSS risk increased",
    "X-XSS-Protection"          : "XSS filter header missing",
    "Referrer-Policy"           : "Referrer-Policy missing — data leakage risk",
    "Permissions-Policy"        : "Permissions-Policy missing",
}

# Headers that leak server info
INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"
]

def get_args():
    parser = argparse.ArgumentParser(
        prog="http_headers.py",
        description="VoidRecon — HTTP Headers & Security Analysis",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 http_headers.py -u target.com
  python3 http_headers.py -u target.com --https
  python3 http_headers.py -u target.com --nikto
  python3 http_headers.py -u target.com --port 8080
  python3 http_headers.py -u target.com --follow
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("--https",
        action="store_true",
        help="Force HTTPS"
    )
    parser.add_argument("--port",
        type=int, default=None,
        help="Custom port (e.g. 8080)"
    )
    parser.add_argument("--nikto",
        action="store_true",
        help="Also run Nikto scan (slower but thorough)"
    )
    parser.add_argument("--follow",
        action="store_true",
        help="Follow redirects"
    )
    parser.add_argument("-o", "--output",
        default="output/json",
        help="Output directory (default: output/json)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def analyze_headers(domain, protocol, port, follow_redirects):
    port_str = f":{port}" if port else ""
    url      = f"{protocol}://{domain}{port_str}"

    log_info(f"Fetching headers from: {Fore.GREEN}{url}{Style.RESET_ALL}")

    try:
        resp = requests.get(
            url,
            timeout=15,
            verify=False,
            allow_redirects=follow_redirects,
            headers={"User-Agent": "VoidRecon/1.0 Security Scanner"}
        )

        headers      = dict(resp.headers)
        status_code  = resp.status_code
        final_url    = resp.url

        log_success(f"Response: {status_code} | Final URL: {final_url}")

        # Check security headers
        missing_headers = []
        present_headers = []

        print(f"\n{Fore.WHITE}  Security Header Analysis:{Style.RESET_ALL}")
        print(f"  {'─'*50}")

        for header, warning in SECURITY_HEADERS.items():
            if header.lower() in [h.lower() for h in headers.keys()]:
                log_present(f"{header}")
                present_headers.append(header)
            else:
                log_missing(f"{header} — {warning}")
                missing_headers.append({
                    "header" : header,
                    "warning": warning
                })

        # Check info leak headers
        leaked_info = {}
        print(f"\n{Fore.WHITE}  Information Disclosure Headers:{Style.RESET_ALL}")
        print(f"  {'─'*50}")

        for header in INFO_LEAK_HEADERS:
            for h_key, h_val in headers.items():
                if h_key.lower() == header.lower():
                    log_warn(f"{h_key}: {h_val} — Server info exposed!")
                    leaked_info[h_key] = h_val

        # Cookie analysis
        cookies = []
        if resp.cookies:
            print(f"\n{Fore.WHITE}  Cookie Analysis:{Style.RESET_ALL}")
            print(f"  {'─'*50}")
            for cookie in resp.cookies:
                cookie_info = {
                    "name"     : cookie.name,
                    "secure"   : cookie.secure,
                    "httponly" : cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite" : cookie.get_nonstandard_attr("SameSite", "Not set")
                }
                cookies.append(cookie_info)
                if not cookie.secure:
                    log_warn(f"Cookie '{cookie.name}' missing Secure flag!")
                else:
                    log_present(f"Cookie '{cookie.name}' has Secure flag")

        return {
            "url"             : url,
            "status_code"     : status_code,
            "all_headers"     : headers,
            "missing_security": missing_headers,
            "present_security": present_headers,
            "info_leaked"     : leaked_info,
            "cookies"         : cookies,
            "security_score"  : len(present_headers),
            "max_score"       : len(SECURITY_HEADERS)
        }

    except requests.exceptions.ConnectionError:
        log_error(f"Cannot connect to {url}")
        return {"error": "Connection failed", "url": url}
    except Exception as e:
        log_error(f"Header fetch error: {e}")
        return {"error": str(e), "url": url}


def run_nikto(domain, protocol, port):
    port_str = f":{port}" if port else ""
    url      = f"{protocol}://{domain}{port_str}"
    log_info(f"Running Nikto on {url} (this may take 2-5 minutes)...")

    try:
        result = subprocess.run(
            ["nikto", "-h", url, "-C", "all", "-Format", "txt"],
            capture_output=True, text=True, timeout=300
        )
        findings = []
        for line in result.stdout.split('\n'):
            if line.startswith('+') and 'OSVDB' not in line:
                finding = line.strip('+ ').strip()
                if finding:
                    findings.append(finding)
                    log_warn(f"Nikto: {finding[:80]}")

        log_success(f"Nikto → {len(findings)} findings")
        return findings
    except subprocess.TimeoutExpired:
        log_warn("Nikto timed out after 5 minutes")
        return []
    except Exception as e:
        log_error(f"Nikto error: {e}")
        return []


def run(domain, output_dir="output/json", https=False,
        port=None, run_nikto_scan=False, follow=False):

    os.makedirs(output_dir, exist_ok=True)
    protocol = "https" if https else "http"

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    log_info(f"Target   : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Protocol : {protocol.upper()}")
    log_info(f"Port     : {port if port else 'default'}")
    log_info(f"Nikto    : {'Enabled' if run_nikto_scan else 'Disabled'}")
    log_info(f"Output   : {output_dir}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")

    header_data  = analyze_headers(domain, protocol, port, follow)
    nikto_data   = []

    if run_nikto_scan:
        nikto_data = run_nikto(domain, protocol, port)

    # Security score
    score     = header_data.get("security_score", 0)
    max_score = header_data.get("max_score", 7)
    grade     = (
        "A" if score >= 6 else
        "B" if score >= 5 else
        "C" if score >= 4 else
        "D" if score >= 2 else "F"
    )

    data = {
        "module"        : "http_headers",
        "domain"        : domain,
        "timestamp"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "protocol"      : protocol,
        "security_score": f"{score}/{max_score}",
        "security_grade": grade,
        "header_analysis": header_data,
        "nikto_findings": nikto_data
    }

    out_path = os.path.join(output_dir, "http_headers.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    grade_color = (
        Fore.GREEN if grade in ["A","B"] else
        Fore.YELLOW if grade == "C" else Fore.RED
    )
    log_success(
        f"Security Grade: {grade_color}{grade}{Style.RESET_ALL} "
        f"({score}/{max_score} headers present)"
    )
    missing = header_data.get("missing_security", [])
    if missing:
        log_warn(f"{len(missing)} security headers missing")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain         = args.url,
        output_dir     = args.output,
        https          = args.https,
        port           = args.port,
        run_nikto_scan = args.nikto,
        follow         = args.follow
    )
