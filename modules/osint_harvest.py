#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — OSINT Harvesting Module
#   Author  : Udit Soam
#   Usage   : python3 osint_harvest.py -u target.com
#             python3 osint_harvest.py -u target.com -s google,bing
#             python3 osint_harvest.py -u target.com --limit 200
#             python3 osint_harvest.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.MAGENTA}
  ██████╗ ███████╗██╗███╗   ██╗████████╗
  ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
  ██║  ██║███████╗██║██╔██╗ ██║   ██║
  ██║  ██║╚════██║██║██║╚██╗██║   ██║
  ██████╔╝███████║██║██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 02 ] OSINT Harvesting — Emails, Hosts, Names{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | VoidRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="osint_harvest.py",
        description="VoidRecon — OSINT Harvesting Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 osint_harvest.py -u target.com
  python3 osint_harvest.py -u target.com -s google,bing,yahoo
  python3 osint_harvest.py -u target.com --limit 200
  python3 osint_harvest.py -u target.com -o /tmp/results
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("-s", "--sources",
        default="google,bing,duckduckgo,yahoo",
        help="Comma-separated sources (default: google,bing,duckduckgo,yahoo)"
    )
    parser.add_argument("-o", "--output",
        default="output/json",
        help="Output directory (default: output/json)"
    )
    parser.add_argument("--limit",
        type=int, default=100,
        help="Max results per source (default: 100)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def harvest_source(domain, source, limit, timeout=60):
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain,
             "-b", source, "-l", str(limit)],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log_warn(f"{source} timed out")
        return ""
    except FileNotFoundError:
        log_error("theHarvester not found → sudo apt install theharvester")
        return ""
    except Exception as e:
        log_error(f"{source} error: {e}")
        return ""


def parse_output(raw, domain):
    emails = set()
    hosts  = set()

    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    for match in email_pattern.findall(raw):
        if domain in match:
            emails.add(match.lower())

    for line in raw.split('\n'):
        line = line.strip()
        if domain in line and '.' in line and '@' not in line:
            cleaned = line.strip('*').strip('-').strip()
            if cleaned:
                hosts.add(cleaned)

    return emails, hosts


def run(domain, output_dir="output/json", sources=None, limit=100):
    os.makedirs(output_dir, exist_ok=True)

    if sources is None:
        sources = ["google", "bing", "duckduckgo", "yahoo"]

    all_emails = set()
    all_hosts  = set()
    source_summary = {}

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"Target  : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Sources : {', '.join(sources)}")
    log_info(f"Limit   : {limit} results per source")
    log_info(f"Output  : {output_dir}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    for source in sources:
        log_info(f"Harvesting from {Fore.YELLOW}{source}{Style.RESET_ALL}...")
        raw = harvest_source(domain, source, limit)
        emails, hosts = parse_output(raw, domain)

        all_emails.update(emails)
        all_hosts.update(hosts)
        source_summary[source] = {
            "emails": len(emails),
            "hosts" : len(hosts)
        }
        log_success(f"{source} → {len(emails)} emails, {len(hosts)} hosts")

    emails_list = sorted(list(all_emails))
    hosts_list  = sorted(list(all_hosts))

    print(f"\n{Fore.WHITE}{'─'*40}{Style.RESET_ALL}")
    log_success(f"Total Emails found: {Fore.YELLOW}{len(emails_list)}{Style.RESET_ALL}")
    for e in emails_list: log_data(e)

    log_success(f"Total Hosts found: {Fore.YELLOW}{len(hosts_list)}{Style.RESET_ALL}")
    for h in hosts_list[:10]: log_data(h)
    if len(hosts_list) > 10:
        log_data(f"... and {len(hosts_list)-10} more")

    data = {
        "module"        : "osint_harvest",
        "domain"        : domain,
        "timestamp"     : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sources_used"  : sources,
        "source_summary": source_summary,
        "total_emails"  : len(emails_list),
        "total_hosts"   : len(hosts_list),
        "emails"        : emails_list,
        "hosts"         : hosts_list
    }

    out_path = os.path.join(output_dir, "osint_harvest.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success(f"DONE → Saved: {out_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args    = get_args()
    sources = [s.strip() for s in args.sources.split(",")]
    if not args.no_banner: banner()
    run(
        domain     = args.url,
        output_dir = args.output,
        sources    = sources,
        limit      = args.limit
    )
