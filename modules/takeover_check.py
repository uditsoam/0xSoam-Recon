#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Subdomain Takeover Check Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
#   Usage   : python3 takeover_check.py -u target.com
#             python3 takeover_check.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, requests, socket
from datetime import datetime
from colorama import Fore, Style, init
requests.packages.urllib3.disable_warnings()
init(autoreset=True)

BANNER = """
\033[91m
 ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗
    ██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
    ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝
    ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
\033[0m
\033[97m  [ Module 11 ] Subdomain Takeover Detection\033[0m
\033[93m  Author: Udit Soam | 0xSoamRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_vuln(msg):    print(f"{Fore.RED}  [VULN] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Service fingerprints ─────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages"   : [
        "There isn't a GitHub Pages site here",
        "For root URLs (like http://example.com/) you must provide an index"
    ],
    "AWS S3"         : [
        "NoSuchBucket",
        "The specified bucket does not exist",
        "BucketNotFound"
    ],
    "Heroku"         : [
        "No such app",
        "herokuapp.com",
        "There's nothing here, yet"
    ],
    "Netlify"        : [
        "Not Found - Request ID",
        "netlify"
    ],
    "Vercel"         : [
        "The deployment could not be found",
        "DEPLOYMENT_NOT_FOUND"
    ],
    "Shopify"        : [
        "Sorry, this shop is currently unavailable",
        "only for shopify"
    ],
    "Ghost"          : [
        "The thing you were looking for is no longer here"
    ],
    "Tumblr"         : [
        "Whatever you were looking for doesn't currently exist"
    ],
    "WordPress.com"  : [
        "Do you want to register"
    ],
    "Zendesk"        : [
        "Help Center Closed"
    ],
    "Desk.com"       : [
        "Sorry, We Couldn't Find That Page"
    ],
    "Fastly"         : [
        "Fastly error: unknown domain"
    ],
    "Pantheon"       : [
        "The gods are wise"
    ],
    "Azure"          : [
        "404 Web Site not found",
        "azure.com"
    ],
    "Cargo"          : [
        "If you're moving your domain away from Cargo"
    ],
    "Unbounce"       : [
        "The requested URL was not found on this server"
    ],
}


def get_args():
    parser = argparse.ArgumentParser(
        prog="takeover_check.py",
        description="0xSoamRecon — Subdomain Takeover Detection",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 takeover_check.py -u target.com
  python3 takeover_check.py -u target.com --threads 20
  python3 takeover_check.py -u target.com -o /tmp/results
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
    parser.add_argument("--threads",
        type=int, default=10,
        help="Threads for checking (default: 10)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def load_subdomains(output_dir, domain):
    subs_file = os.path.join(output_dir, "subdomain_enum.json")
    subdomains = []

    if os.path.exists(subs_file):
        try:
            with open(subs_file) as f:
                data = json.load(f)
            subdomains = data.get("subdomains", [])
            log_success(f"Loaded {len(subdomains)} subdomains from subdomain_enum.json")
        except Exception as e:
            log_error(f"Could not read subdomain_enum.json: {e}")
    else:
        log_warn("subdomain_enum.json not found — using main domain only")
        subdomains = [domain]

    return subdomains


def resolve_domain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None


def check_cname(subdomain):
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", subdomain],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip()
        return cname if cname else None
    except Exception:
        return None


def check_takeover(subdomain):
    result = {
        "subdomain"  : subdomain,
        "ip"         : None,
        "cname"      : None,
        "status"     : None,
        "vulnerable" : False,
        "service"    : None,
        "evidence"   : None
    }

    # DNS resolution
    ip = resolve_domain(subdomain)
    result["ip"] = ip

    # CNAME check
    cname = check_cname(subdomain)
    result["cname"] = cname

    # If no DNS — dangling DNS possible
    if not ip:
        result["status"]    = "NXDOMAIN"
        result["vulnerable"] = True
        result["evidence"]  = "Domain does not resolve — dangling DNS record"
        log_vuln(f"{subdomain} — NXDOMAIN — possible dangling DNS!")
        return result

    # HTTP check
    for protocol in ["http", "https"]:
        try:
            resp = requests.get(
                f"{protocol}://{subdomain}",
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "0xSoamRecon/1.0"}
            )
            result["status"] = resp.status_code
            body = resp.text.lower()

            # Check fingerprints
            for service, patterns in TAKEOVER_FINGERPRINTS.items():
                for pattern in patterns:
                    if pattern.lower() in body:
                        result["vulnerable"] = True
                        result["service"]    = service
                        result["evidence"]   = pattern
                        log_vuln(
                            f"{subdomain} → VULNERABLE to {service} takeover!"
                        )
                        log_data(f"Evidence: {pattern}")
                        return result

            break

        except requests.exceptions.SSLError:
            continue
        except Exception:
            result["status"] = "CONNECTION_FAILED"

    if not result["vulnerable"]:
        log_data(f"{subdomain} → {ip} — Clean")

    return result


def run(domain, output_dir="output/json", threads=10):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target   : {domain}")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    # Load subdomains
    subdomains = load_subdomains(output_dir, domain)
    log_info(f"Checking {len(subdomains)} subdomains for takeover...")
    print()

    results     = []
    vulnerable  = []

    for i, subdomain in enumerate(subdomains, 1):
        log_info(f"[{i}/{len(subdomains)}] Checking: {subdomain}")
        result = check_takeover(subdomain)
        results.append(result)
        if result["vulnerable"]:
            vulnerable.append(result)

    data = {
        "module"              : "takeover_check",
        "domain"              : domain,
        "timestamp"           : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_checked"       : len(results),
        "total_vulnerable"    : len(vulnerable),
        "vulnerable_subdomains": vulnerable,
        "all_results"         : results
    }

    out_path = os.path.join(output_dir, "takeover_check.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"Takeover Check Complete")
    log_success(f"Checked    : {len(results)} subdomains")

    if vulnerable:
        log_vuln(f"VULNERABLE : {len(vulnerable)} subdomains at risk!")
        for v in vulnerable:
            log_vuln(f"  {v['subdomain']} → {v.get('service','Unknown')}")
    else:
        log_success("No takeover vulnerabilities found")

    log_success(f"Saved → {out_path}")
    print(f"\033[97m{'═'*60}\033[0m\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner:
        banner()
    run(
        domain     = args.url,
        output_dir = args.output,
        threads    = args.threads
    )
