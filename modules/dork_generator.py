#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Google Dork Generator Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
#   Usage   : python3 dork_generator.py -u target.com
#             python3 dork_generator.py -u target.com --category sensitive
#             python3 dork_generator.py -u target.com --open
#             python3 dork_generator.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse, webbrowser, time
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[93m
 ██████╗  ██████╗ ██████╗ ██╗  ██╗
 ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝
 ██║  ██║██║   ██║██████╔╝█████╔╝
 ██║  ██║██║   ██║██╔══██╗██╔═██╗
 ██████╔╝╚██████╔╝██║  ██║██║  ██╗
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  GENERATOR
\033[0m
\033[97m  [ Module 16 ] Google Dork Generator\033[0m
\033[93m  Author: Udit Soam | 0xSoamRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_dork(msg):    print(f"{Fore.YELLOW}      [DORK] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Dork Templates ───────────────────────────────────────────
DORK_CATEGORIES = {

    "sensitive_files": {
        "label"  : "Sensitive Files",
        "color"  : Fore.RED,
        "dorks"  : [
            'site:{domain} filetype:pdf',
            'site:{domain} filetype:xls',
            'site:{domain} filetype:xlsx',
            'site:{domain} filetype:csv',
            'site:{domain} filetype:sql',
            'site:{domain} filetype:env',
            'site:{domain} filetype:log',
            'site:{domain} filetype:cfg',
            'site:{domain} filetype:conf',
            'site:{domain} filetype:bak',
            'site:{domain} filetype:zip',
            'site:{domain} filetype:tar',
            'site:{domain} filetype:gz',
            'site:{domain} filetype:pem',
            'site:{domain} filetype:key',
            'site:{domain} filetype:p12',
            'site:{domain} filetype:pfx',
            'site:{domain} filetype:txt',
            'site:{domain} filetype:xml',
            'site:{domain} filetype:json',
        ]
    },

    "admin_panels": {
        "label"  : "Admin Panels & Login Pages",
        "color"  : Fore.RED,
        "dorks"  : [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:administrator',
            'site:{domain} inurl:login',
            'site:{domain} inurl:signin',
            'site:{domain} inurl:dashboard',
            'site:{domain} inurl:panel',
            'site:{domain} inurl:cpanel',
            'site:{domain} inurl:webmail',
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:wp-login',
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} inurl:manage',
            'site:{domain} inurl:control',
            'site:{domain} inurl:portal',
            'site:{domain} inurl:console',
        ]
    },

    "exposed_data": {
        "label"  : "Exposed Data & Directory Listings",
        "color"  : Fore.YELLOW,
        "dorks"  : [
            'site:{domain} inurl:config',
            'site:{domain} inurl:backup',
            'site:{domain} inurl:db',
            'site:{domain} inurl:database',
            'site:{domain} inurl:dump',
            'site:{domain} inurl:export',
            'site:{domain} inurl:upload',
            'site:{domain} inurl:uploads',
            'site:{domain} "index of /"',
            'site:{domain} intitle:"index of"',
            'site:{domain} intitle:"directory listing"',
            'site:{domain} inurl:/.git',
            'site:{domain} inurl:/.svn',
            'site:{domain} inurl:/.env',
            'site:{domain} inurl:/etc/passwd',
        ]
    },

    "credentials": {
        "label"  : "Credentials & Secrets",
        "color"  : Fore.RED,
        "dorks"  : [
            'site:{domain} intext:password',
            'site:{domain} intext:passwd',
            'site:{domain} intext:username',
            'site:{domain} intext:"api_key"',
            'site:{domain} intext:"api_secret"',
            'site:{domain} intext:"secret_key"',
            'site:{domain} intext:"access_token"',
            'site:{domain} intext:"private_key"',
            'site:{domain} intext:"aws_secret"',
            'site:{domain} intext:"db_password"',
            'site:{domain} intext:"mysql_password"',
            'site:{domain} intext:BEGIN PRIVATE KEY',
            'site:{domain} intext:BEGIN RSA PRIVATE KEY',
        ]
    },

    "subdomains": {
        "label"  : "Subdomain Discovery",
        "color"  : Fore.CYAN,
        "dorks"  : [
            'site:*.{domain}',
            'site:{domain} -www',
            'site:{domain} -www -mail',
            'site:*.{domain} -www',
            'inurl:{domain}',
            'link:{domain}',
        ]
    },

    "technology": {
        "label"  : "Technology & CMS",
        "color"  : Fore.MAGENTA,
        "dorks"  : [
            'site:{domain} inurl:wp-admin',
            'site:{domain} inurl:wp-content',
            'site:{domain} inurl:wp-includes',
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} inurl:drupal',
            'site:{domain} inurl:joomla',
            'site:{domain} inurl:magento',
            'site:{domain} inurl:prestashop',
            'site:{domain} inurl:laravel',
            'site:{domain} inurl:django',
            'site:{domain} inurl:rails',
            'site:{domain} inurl:swagger',
            'site:{domain} inurl:graphql',
            'site:{domain} inurl:api/v1',
            'site:{domain} inurl:api/v2',
        ]
    },

    "error_pages": {
        "label"  : "Error Pages & Debug Info",
        "color"  : Fore.YELLOW,
        "dorks"  : [
            'site:{domain} intext:"Fatal error"',
            'site:{domain} intext:"Warning: mysql"',
            'site:{domain} intext:"PHP Parse error"',
            'site:{domain} intext:"Stack Trace"',
            'site:{domain} intext:"sql syntax"',
            'site:{domain} intext:"ORA-" error',
            'site:{domain} intext:"Microsoft OLE DB"',
            'site:{domain} intitle:"500 Internal Server Error"',
            'site:{domain} intitle:"403 Forbidden"',
            'site:{domain} intext:"debug" inurl:debug',
        ]
    },

    "network_devices": {
        "label"  : "Network Devices & IoT",
        "color"  : Fore.CYAN,
        "dorks"  : [
            'site:{domain} intitle:"router"',
            'site:{domain} intitle:"firewall"',
            'site:{domain} inurl:8080',
            'site:{domain} inurl:8443',
            'site:{domain} inurl:9090',
            'site:{domain} intitle:"webcam"',
            'site:{domain} intitle:"network camera"',
            'site:{domain} inurl:cgi-bin',
        ]
    }
}


def get_args():
    parser = argparse.ArgumentParser(
        prog="dork_generator.py",
        description="0xSoamRecon — Google Dork Generator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 dork_generator.py -u target.com
  python3 dork_generator.py -u target.com --category sensitive_files
  python3 dork_generator.py -u target.com --category admin_panels
  python3 dork_generator.py -u target.com --open
  python3 dork_generator.py -u target.com --category all -o /tmp/results

Categories:
  all             — All categories
  sensitive_files — File extensions
  admin_panels    — Login & admin pages
  exposed_data    — Directory listings
  credentials     — Passwords & secrets
  subdomains      — Subdomain discovery
  technology      — CMS & frameworks
  error_pages     — Debug & error info
  network_devices — Routers & IoT
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
    parser.add_argument("--category",
        default="all",
        help="Dork category to generate (default: all)"
    )
    parser.add_argument("--open",
        action="store_true",
        help="Open first dork of each category in browser"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def generate_dorks(domain, category="all"):
    result = {}

    if category == "all":
        cats = DORK_CATEGORIES
    elif category in DORK_CATEGORIES:
        cats = {category: DORK_CATEGORIES[category]}
    else:
        log_error(f"Unknown category: {category}")
        log_warn(f"Available: {list(DORK_CATEGORIES.keys())}")
        cats = DORK_CATEGORIES

    for cat_key, cat_data in cats.items():
        label  = cat_data["label"]
        color  = cat_data["color"]
        dorks  = [
            d.format(domain=domain)
            for d in cat_data["dorks"]
        ]
        result[cat_key] = {
            "label" : label,
            "dorks" : dorks,
            "count" : len(dorks)
        }

        print(f"\n{color}  ── {label} ({len(dorks)} dorks) ──{Style.RESET_ALL}")
        for dork in dorks:
            log_dork(dork)

    return result


def save_dork_txt(domain, all_dorks_flat, output_dir):
    safe_domain = domain.replace(".", "_")
    txt_path    = os.path.join(
        output_dir, f"dorks_{safe_domain}.txt"
    )
    try:
        with open(txt_path, "w") as f:
            f.write(f"# 0xSoamRecon — Google Dorks for {domain}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Author: Udit Soam | github.com/uditsoam/0xSoamRecon\n")
            f.write(f"# Total dorks: {len(all_dorks_flat)}\n\n")
            for dork in all_dorks_flat:
                f.write(f"{dork}\n")
        log_success(f"Dork list saved → {txt_path}")
        return txt_path
    except Exception as e:
        log_error(f"Could not save txt file: {e}")
        return None


def open_in_browser(dorks_by_category, delay=2):
    log_info("Opening first dork of each category in browser...")
    log_warn("Opening with 2 second delay between tabs")

    for cat_key, cat_data in dorks_by_category.items():
        dorks = cat_data.get("dorks", [])
        if dorks:
            first_dork = dorks[0]
            search_url = (
                "https://www.google.com/search?q="
                + first_dork.replace(" ", "+")
            )
            log_data(f"Opening: {first_dork}")
            try:
                webbrowser.open(search_url)
                time.sleep(delay)
            except Exception as e:
                log_error(f"Could not open browser: {e}")


def run(domain, output_dir="output/json",
        category="all", open_browser=False):

    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target    : {domain}")
    log_info(f"Category  : {category}")
    log_info(f"Output    : {output_dir}")
    log_info(f"Browser   : {'Yes — opening tabs' if open_browser else 'No'}")
    log_info(f"Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m")

    # Generate dorks
    dorks_by_cat = generate_dorks(domain, category)

    # Flatten all dorks
    all_dorks_flat = []
    total_count    = 0
    for cat_data in dorks_by_cat.values():
        all_dorks_flat.extend(cat_data["dorks"])
        total_count += cat_data["count"]

    # Save txt file
    txt_path = save_dork_txt(domain, all_dorks_flat, output_dir)

    # Open in browser
    if open_browser:
        open_in_browser(dorks_by_cat)

    # Build JSON
    data = {
        "module"        : "dork_generator",
        "domain"        : domain,
        "timestamp"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category"      : category,
        "total_dorks"   : total_count,
        "categories"    : dorks_by_cat,
        "all_dorks"     : all_dorks_flat,
        "txt_file"      : txt_path
    }

    out_path = os.path.join(output_dir, "dork_generator.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"Dork Generation Complete")
    log_success(f"Total dorks     : {total_count}")
    log_success(f"Categories      : {len(dorks_by_cat)}")
    log_success(f"JSON saved      → {out_path}")
    if txt_path:
        log_success(f"TXT saved       → {txt_path}")
    print(f"\n  {Fore.YELLOW}Tip: Copy dorks from txt file and")
    print(f"  paste directly into Google Search{Style.RESET_ALL}")
    print(f"\033[97m{'═'*60}\033[0m\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner:
        banner()
    run(
        domain       = args.url,
        output_dir   = args.output,
        category     = args.category,
        open_browser = args.open
    )
