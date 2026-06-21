#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Tech Stack Fingerprint Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
#   Usage   : python3 tech_stack.py -u target.com
#             python3 tech_stack.py -u target.com --deep
#             python3 tech_stack.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, requests
from datetime import datetime
from colorama import Fore, Style, init
requests.packages.urllib3.disable_warnings()
init(autoreset=True)

BANNER = """
\033[95m
 ████████╗███████╗ ██████╗██╗  ██╗    ███████╗████████╗ █████╗  ██████╗██╗  ██╗
    ██╔══╝██╔════╝██╔════╝██║  ██║    ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
    ██║   █████╗  ██║     ███████║    ███████╗   ██║   ███████║██║     █████╔╝
    ██║   ██╔══╝  ██║     ██╔══██║    ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
    ██║   ███████╗╚██████╗██║  ██║    ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
    ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
\033[0m
\033[97m  [ Module 10 ] Tech Stack Fingerprinting\033[0m
\033[93m  Author: Udit Soam | 0xSoamRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Known tech fingerprints ──────────────────────────────────
HEADER_FINGERPRINTS = {
    "X-Powered-By"          : "server_tech",
    "Server"                : "server",
    "X-Generator"           : "cms",
    "X-Drupal-Cache"        : "cms",
    "X-Wordpress-Cache"     : "cms",
    "X-Shopify-Stage"       : "platform",
    "X-AspNet-Version"      : "framework",
    "X-AspNetMvc-Version"   : "framework",
    "CF-Cache-Status"       : "cdn",
    "X-Cache"               : "cdn",
    "Via"                   : "cdn",
}

CMS_FINGERPRINTS = {
    "wp-content"            : "WordPress",
    "wp-includes"           : "WordPress",
    "wp-json"               : "WordPress",
    "Drupal"                : "Drupal",
    "drupal"                : "Drupal",
    "joomla"                : "Joomla",
    "Joomla"                : "Joomla",
    "laravel"               : "Laravel",
    "Laravel"               : "Laravel",
    "django"                : "Django",
    "Django"                : "Django",
    "symfony"               : "Symfony",
    "codeigniter"           : "CodeIgniter",
    "shopify"               : "Shopify",
    "wix"                   : "Wix",
    "squarespace"           : "Squarespace",
    "magento"               : "Magento",
    "prestashop"            : "PrestaShop",
}

CDN_FINGERPRINTS = {
    "cloudflare"            : "Cloudflare",
    "Cloudflare"            : "Cloudflare",
    "akamai"                : "Akamai",
    "fastly"                : "Fastly",
    "amazonaws"             : "AWS CloudFront",
    "cloudfront"            : "AWS CloudFront",
    "azureedge"             : "Azure CDN",
    "googleusercontent"     : "Google Cloud",
}

JS_LIBRARIES = {
    "jquery"                : "jQuery",
    "react"                 : "React",
    "angular"               : "Angular",
    "vue"                   : "Vue.js",
    "bootstrap"             : "Bootstrap",
    "lodash"                : "Lodash",
    "axios"                 : "Axios",
    "next"                  : "Next.js",
    "nuxt"                  : "Nuxt.js",
    "webpack"               : "Webpack",
    "moment"                : "Moment.js",
}

def get_args():
    parser = argparse.ArgumentParser(
        prog="tech_stack.py",
        description="0xSoamRecon — Tech Stack Fingerprinting Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 tech_stack.py -u target.com
  python3 tech_stack.py -u target.com --deep
  python3 tech_stack.py -u target.com --https
  python3 tech_stack.py -u target.com -o /tmp/results
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
    parser.add_argument("--deep",
        action="store_true",
        help="Deep scan — check /robots.txt, /sitemap.xml, common paths"
    )
    parser.add_argument("--https",
        action="store_true",
        help="Force HTTPS"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def run_whatweb(domain, protocol):
    log_info("Running WhatWeb...")
    try:
        result = subprocess.run(
            ["whatweb", "--color=never",
             "--log-brief=/dev/stdout",
             f"{protocol}://{domain}"],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()
        log_success(f"WhatWeb output captured")
        return output
    except FileNotFoundError:
        log_warn("WhatWeb not found — sudo apt install whatweb")
        return ""
    except subprocess.TimeoutExpired:
        log_warn("WhatWeb timed out")
        return ""
    except Exception as e:
        log_error(f"WhatWeb error: {e}")
        return ""


def parse_whatweb(raw_output):
    findings = []
    if not raw_output:
        return findings
    for line in raw_output.split('\n'):
        if line.strip():
            findings.append(line.strip())
    return findings


def fetch_page(url, timeout=15):
    try:
        resp = requests.get(
            url, timeout=timeout,
            verify=False,
            headers={"User-Agent": "0xSoamRecon/1.0"},
            allow_redirects=True
        )
        return resp
    except Exception:
        return None


def analyze_headers(resp):
    if not resp:
        return {}, {}, []

    headers  = dict(resp.headers)
    server   = {}
    cdn      = {}
    detected = []

    for header, category in HEADER_FINGERPRINTS.items():
        for h_key, h_val in headers.items():
            if h_key.lower() == header.lower():
                detected.append({
                    "header"  : h_key,
                    "value"   : h_val,
                    "category": category
                })
                log_data(f"{h_key}: {h_val}")

    return headers, detected


def detect_cms(resp, whatweb_raw):
    if not resp:
        return []
    detected = []
    body     = resp.text.lower() if resp else ""
    combined = body + whatweb_raw.lower()

    for keyword, cms_name in CMS_FINGERPRINTS.items():
        if keyword.lower() in combined:
            if cms_name not in detected:
                detected.append(cms_name)
                log_data(f"CMS detected: {cms_name}")

    return list(set(detected))


def detect_cdn(resp):
    if not resp:
        return []
    detected = []
    headers  = str(dict(resp.headers)).lower()

    for keyword, cdn_name in CDN_FINGERPRINTS.items():
        if keyword.lower() in headers:
            if cdn_name not in detected:
                detected.append(cdn_name)
                log_data(f"CDN detected: {cdn_name}")

    return list(set(detected))


def detect_js_libs(resp):
    if not resp:
        return []
    detected = []
    body     = resp.text.lower() if resp else ""

    for keyword, lib_name in JS_LIBRARIES.items():
        if keyword.lower() in body:
            if lib_name not in detected:
                detected.append(lib_name)
                log_data(f"JS Library: {lib_name}")

    return list(set(detected))


def deep_scan(domain, protocol):
    log_info("Running deep scan on common paths...")
    interesting = []
    paths = [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/readme.html", "/wp-login.php", "/admin", "/login",
        "/.git/HEAD", "/.env", "/config.php", "/phpinfo.php",
        "/server-status", "/api", "/graphql", "/swagger.json"
    ]

    for path in paths:
        url  = f"{protocol}://{domain}{path}"
        resp = fetch_page(url, timeout=8)
        if resp and resp.status_code in [200, 301, 302, 403]:
            entry = {
                "path"  : path,
                "status": resp.status_code,
                "size"  : len(resp.content)
            }
            interesting.append(entry)
            if resp.status_code == 200:
                log_warn(f"[{resp.status_code}] {path} — ACCESSIBLE")
            else:
                log_data(f"[{resp.status_code}] {path}")

    log_success(f"Deep scan found {len(interesting)} accessible paths")
    return interesting


def run(domain, output_dir="output/json",
        deep=False, https=False):

    os.makedirs(output_dir, exist_ok=True)
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{domain}"

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target   : {domain}")
    log_info(f"URL      : {base_url}")
    log_info(f"Mode     : {'Deep Scan' if deep else 'Standard'}")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    # WhatWeb scan
    whatweb_raw     = run_whatweb(domain, protocol)
    whatweb_parsed  = parse_whatweb(whatweb_raw)

    # Fetch main page
    log_info(f"Fetching {base_url}...")
    resp = fetch_page(base_url)

    if resp:
        log_success(f"Response: {resp.status_code} | "
                    f"Size: {len(resp.content)} bytes")
    else:
        log_warn("Could not fetch main page")

    # Analyze
    log_info("Analyzing headers...")
    all_headers, header_findings = analyze_headers(resp)

    log_info("Detecting CMS...")
    cms_detected = detect_cms(resp, whatweb_raw)

    log_info("Detecting CDN...")
    cdn_detected = detect_cdn(resp)

    log_info("Detecting JS Libraries...")
    js_libs = detect_js_libs(resp)

    # Server info
    server_info = all_headers.get("Server", "Unknown")
    powered_by  = all_headers.get("X-Powered-By", "Unknown")

    # Deep scan
    deep_findings = []
    if deep:
        deep_findings = deep_scan(domain, protocol)

    # Build result
    data = {
        "module"          : "tech_stack",
        "domain"          : domain,
        "timestamp"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "base_url"        : base_url,
        "server"          : server_info,
        "powered_by"      : powered_by,
        "cms"             : cms_detected,
        "cdn"             : cdn_detected,
        "js_libraries"    : js_libs,
        "header_findings" : header_findings,
        "whatweb"         : whatweb_parsed,
        "deep_scan"       : deep_findings,
        "interesting_findings": [
            p for p in deep_findings
            if p.get("status") == 200
        ]
    }

    out_path = os.path.join(output_dir, "tech_stack.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"Tech Stack Fingerprint Complete")
    log_success(f"Server      : {server_info}")
    log_success(f"Powered By  : {powered_by}")
    log_success(f"CMS         : {cms_detected if cms_detected else 'Not detected'}")
    log_success(f"CDN         : {cdn_detected if cdn_detected else 'Not detected'}")
    log_success(f"JS Libraries: {js_libs if js_libs else 'Not detected'}")
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
        deep       = args.deep,
        https      = args.https
    )
