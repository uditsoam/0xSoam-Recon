#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — GitHub Dorking Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
#   Usage   : python3 github_dork.py -u target.com
#             python3 github_dork.py -u target.com --limit 20
#             python3 github_dork.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse, requests, time, yaml
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[92m
  ██████╗ ██╗████████╗██╗  ██╗██╗   ██╗██████╗
 ██╔════╝ ██║╚══██╔══╝██║  ██║██║   ██║██╔══██╗
 ██║  ███╗██║   ██║   ███████║██║   ██║██████╔╝
 ██║   ██║██║   ██║   ██╔══██║██║   ██║██╔══██╗
 ╚██████╔╝██║   ██║   ██║  ██║╚██████╔╝██████╔╝
  ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  DORK
\033[0m
\033[97m  [ Module 12 ] GitHub Dorking — Leaked Secrets & Code\033[0m
\033[93m  Author: Udit Soam | 0xSoamRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_vuln(msg):    print(f"{Fore.RED}  [LEAK] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

# ── Search queries ───────────────────────────────────────────
DORK_QUERIES = [
    ("{domain} password",       "Credentials"),
    ("{domain} api_key",        "API Key"),
    ("{domain} secret",         "Secret"),
    ("{domain} .env",           "Environment File"),
    ("{domain} config",         "Config File"),
    ("{domain} token",          "Token"),
    ("{domain} private_key",    "Private Key"),
    ("{domain} aws_secret",     "AWS Secret"),
    ("{domain} db_password",    "Database Password"),
    ("{domain} smtp_password",  "SMTP Password"),
]

def get_args():
    parser = argparse.ArgumentParser(
        prog="github_dork.py",
        description="0xSoamRecon — GitHub Dorking Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 github_dork.py -u target.com
  python3 github_dork.py -u target.com --limit 20
  python3 github_dork.py -u target.com -o /tmp/results
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
        type=int, default=10,
        help="Max results per query (default: 10)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def load_token():
    try:
        with open("config/config.yaml") as f:
            config = yaml.safe_load(f)
        token = config.get("github", {}).get("token", "")
        if not token or token == "USER_GITHUB_TOKEN":
            return None
        return token
    except Exception as e:
        log_error(f"config.yaml error: {e}")
        return None


def search_github(query, token, limit=10):
    headers = {
        "Accept"       : "application/vnd.github.v3+json",
        "User-Agent"   : "0xSoamRecon/1.0"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    params = {
        "q"       : query,
        "per_page": min(limit, 30),
        "page"    : 1
    }

    try:
        resp = requests.get(
            "https://api.github.com/search/code",
            headers = headers,
            params  = params,
            timeout = 15
        )

        if resp.status_code == 401:
            log_error("GitHub token invalid or expired")
            return []
        if resp.status_code == 403:
            log_warn("GitHub rate limit hit — waiting 10 seconds")
            time.sleep(10)
            return []
        if resp.status_code == 422:
            log_warn(f"Query too short or invalid: {query}")
            return []
        if resp.status_code != 200:
            log_warn(f"GitHub API status: {resp.status_code}")
            return []

        data  = resp.json()
        items = data.get("items", [])
        return items

    except Exception as e:
        log_error(f"GitHub search error: {e}")
        return []


def parse_results(items, query, category):
    findings = []
    for item in items:
        finding = {
            "query"    : query,
            "category" : category,
            "repo"     : item.get("repository", {}).get("full_name", ""),
            "repo_url" : item.get("repository", {}).get("html_url", ""),
            "file_path": item.get("path", ""),
            "file_url" : item.get("html_url", ""),
            "score"    : item.get("score", 0)
        }
        findings.append(finding)
        log_vuln(
            f"[{category}] {finding['repo']} → {finding['file_path']}"
        )
        log_data(f"URL: {finding['file_url']}")
    return findings


def run(domain, output_dir="output/json", limit=10):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target   : {domain}")
    log_info(f"Queries  : {len(DORK_QUERIES)}")
    log_info(f"Limit    : {limit} per query")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    token = load_token()
    if not token:
        log_warn("No GitHub token found in config.yaml")
        log_warn("Without token: 10 requests/min limit applies")
        log_warn("Add token to config/config.yaml for better results")
    else:
        log_success("GitHub token loaded")

    all_findings   = []
    query_summary  = {}

    for query_template, category in DORK_QUERIES:
        query = query_template.format(domain=domain)
        log_info(f"Searching: {query}")

        items    = search_github(query, token, limit)
        findings = parse_results(items, query, category)

        all_findings.extend(findings)
        query_summary[category] = len(findings)

        log_success(f"{category} → {len(findings)} results")

        # Rate limit respect
        time.sleep(2)

    # Deduplicate by file_url
    seen     = set()
    unique   = []
    for f in all_findings:
        if f["file_url"] not in seen:
            seen.add(f["file_url"])
            unique.append(f)

    data = {
        "module"        : "github_dork",
        "domain"        : domain,
        "timestamp"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_queries" : len(DORK_QUERIES),
        "total_found"   : len(unique),
        "query_summary" : query_summary,
        "findings"      : unique
    }

    out_path = os.path.join(output_dir, "github_dork.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"GitHub Dorking Complete")
    log_success(f"Total unique findings : {len(unique)}")
    if unique:
        log_warn("Review findings manually — may contain false positives")
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
        limit      = args.limit
    )
