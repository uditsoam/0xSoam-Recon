#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Wayback Machine Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
#   Usage   : python3 wayback.py -u target.com
#             python3 wayback.py -u target.com --limit 200
#             python3 wayback.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse, requests
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[93m
 ██╗    ██╗ █████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗
 ██║    ██║██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
 ██║ █╗ ██║███████║ ╚████╔╝ ██████╔╝███████║██║     █████╔╝
 ██║███╗██║██╔══██║  ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗
 ╚███╔███╔╝██║  ██║   ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗
  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
\033[0m
\033[97m  [ Module 13 ] Wayback Machine — Historical URL Discovery\033[0m
\033[93m  Author: Udit Soam | 0xSoamRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_juicy(msg):   print(f"{Fore.RED}  [JUICY] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Interesting patterns to flag ─────────────────────────────
JUICY_EXTENSIONS = [
    ".sql", ".bak", ".zip", ".tar", ".gz", ".rar",
    ".env", ".log", ".cfg", ".conf", ".config",
    ".xml", ".json", ".csv", ".xls", ".xlsx",
    ".pdf", ".doc", ".docx", ".pem", ".key",
    ".pfx", ".p12", ".crt", ".cer"
]

JUICY_KEYWORDS = [
    "admin", "login", "password", "passwd", "secret",
    "backup", "config", "database", "db", "dump",
    "export", "upload", "shell", "cmd", "console",
    "phpinfo", "phpmyadmin", "wp-admin", "cpanel",
    "webmail", "ftp", "ssh", "api", "token",
    "private", "internal", "staging", "dev", "test"
]

def get_args():
    parser = argparse.ArgumentParser(
        prog="wayback.py",
        description="0xSoamRecon — Wayback Machine Historical URL Discovery",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 wayback.py -u target.com
  python3 wayback.py -u target.com --limit 200
  python3 wayback.py -u target.com --from-year 2018
  python3 wayback.py -u target.com -o /tmp/results
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
    parser.add_argument("--limit",
        type=int, default=100,
        help="Max URLs to fetch (default: 100)"
    )
    parser.add_argument("--from-year",
        type=int, default=2015,
        help="Fetch URLs from this year onwards (default: 2015)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def fetch_wayback_urls(domain, limit, from_year):
    log_info(f"Querying Wayback Machine CDX API...")
    log_info(f"Domain: {domain} | Limit: {limit} | From: {from_year}")

    url    = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url"      : f"*.{domain}/*",
        "output"   : "json",
        "fl"       : "original,statuscode,timestamp",
        "collapse" : "urlkey",
        "limit"    : limit,
        "from"     : f"{from_year}0101",
        "filter"   : "statuscode:200"
    }

    try:
        resp = requests.get(
            url, params=params,
            timeout=30
        )

        if resp.status_code != 200:
            log_error(f"Wayback API returned: {resp.status_code}")
            return []

        data = resp.json()

        # First row is header
        if not data or len(data) < 2:
            log_warn("No historical URLs found")
            return []

        # Skip header row
        urls = []
        for row in data[1:]:
            if len(row) >= 3:
                urls.append({
                    "url"       : row[0],
                    "status"    : row[1],
                    "timestamp" : row[2]
                })

        log_success(f"Fetched {len(urls)} historical URLs")
        return urls

    except requests.exceptions.Timeout:
        log_error("Wayback Machine request timed out")
        return []
    except Exception as e:
        log_error(f"Wayback API error: {e}")
        return []


def classify_url(url_entry):
    url   = url_entry.get("url", "").lower()
    flags = []

    # Check extensions
    for ext in JUICY_EXTENSIONS:
        if url.endswith(ext) or f"{ext}?" in url:
            flags.append(f"extension:{ext}")

    # Check keywords
    for keyword in JUICY_KEYWORDS:
        if keyword in url:
            flags.append(f"keyword:{keyword}")

    url_entry["juicy"]  = len(flags) > 0
    url_entry["flags"]  = flags
    return url_entry


def run(domain, output_dir="output/json",
        limit=100, from_year=2015):

    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target    : {domain}")
    log_info(f"Limit     : {limit} URLs")
    log_info(f"From Year : {from_year}")
    log_info(f"Output    : {output_dir}")
    log_info(f"Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    # Fetch URLs
    raw_urls = fetch_wayback_urls(domain, limit, from_year)

    if not raw_urls:
        log_warn("No URLs fetched from Wayback Machine")
        data = {
            "module"           : "wayback",
            "domain"           : domain,
            "timestamp"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_urls"       : 0,
            "interesting_urls" : [],
            "all_urls"         : []
        }
        out_path = os.path.join(output_dir, "wayback.json")
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return data

    # Classify each URL
    log_info("Classifying URLs for interesting patterns...")
    classified = [classify_url(u) for u in raw_urls]

    # Separate juicy ones
    interesting = [u for u in classified if u.get("juicy")]
    normal      = [u for u in classified if not u.get("juicy")]

    # Print interesting ones
    if interesting:
        print(f"\n{Fore.WHITE}  Interesting URLs Found:{Style.RESET_ALL}")
        print(f"  {'─'*50}")
        for u in interesting[:30]:
            log_juicy(f"{u['url']}")
            log_data(f"Flags: {u['flags']}")

    # Category breakdown
    categories = {}
    for u in interesting:
        for flag in u.get("flags", []):
            cat = flag.split(":")[0]
            categories[cat] = categories.get(cat, 0) + 1

    data = {
        "module"           : "wayback",
        "domain"           : domain,
        "timestamp"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "from_year"        : from_year,
        "total_urls"       : len(classified),
        "interesting_count": len(interesting),
        "categories"       : categories,
        "interesting_urls" : interesting,
        "all_urls"         : classified
    }

    out_path = os.path.join(output_dir, "wayback.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"Wayback Machine Scan Complete")
    log_success(f"Total URLs fetched   : {len(classified)}")
    log_success(f"Interesting URLs     : {len(interesting)}")
    if categories:
        log_warn(f"Categories found: {categories}")
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
        limit      = args.limit,
        from_year  = args.from_year
    )
