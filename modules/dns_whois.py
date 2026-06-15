#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — DNS & Whois Module
#   Author  : Udit Soam
#   Usage   : python3 dns_whois.py -u target.com
#             python3 dns_whois.py -u target.com --records A,MX,TXT
#             python3 dns_whois.py -u target.com --no-whois
#             python3 dns_whois.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.BLUE}
  ██████╗ ███╗   ██╗███████╗
  ██╔══██╗████╗  ██║██╔════╝
  ██║  ██║██╔██╗ ██║███████╗
  ██║  ██║██║╚██╗██║╚════██║
  ██████╔╝██║ ╚████║███████║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝  + WHOIS
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 04 ] DNS Records & Whois Intelligence{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | VoidRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.BLUE}      → {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="dns_whois.py",
        description="VoidRecon — DNS Records & Whois Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 dns_whois.py -u target.com
  python3 dns_whois.py -u target.com --records A,MX,TXT,NS
  python3 dns_whois.py -u target.com --no-whois
  python3 dns_whois.py -u target.com -o /tmp/results
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("--records",
        default="A,MX,TXT,NS,CNAME,AAAA,SOA",
        help="DNS record types (default: A,MX,TXT,NS,CNAME,AAAA,SOA)"
    )
    parser.add_argument("--no-whois",
        action="store_true",
        help="Skip Whois lookup"
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


def get_dns(domain, rtype, timeout=15):
    try:
        result = subprocess.run(
            ["dig", "+short", rtype, domain],
            capture_output=True, text=True, timeout=timeout
        )
        records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
        return records
    except Exception as e:
        return []


def get_whois(domain, timeout=20):
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=timeout
        )
        raw = result.stdout

        parsed = {}
        fields = {
            "Registrar"              : "Registrar:",
            "Creation Date"          : "Creation Date:",
            "Expiry Date"            : "Registry Expiry Date:",
            "Registrant Organization": "Registrant Organization:",
            "Registrant Country"     : "Registrant Country:",
            "Name Server"            : "Name Server:",
            "DNSSEC"                 : "DNSSEC:",
            "Updated Date"           : "Updated Date:"
        }
        for key, pattern in fields.items():
            for line in raw.split('\n'):
                if pattern.lower() in line.lower():
                    value = line.split(":", 1)[-1].strip()
                    if value and key not in parsed:
                        parsed[key] = value
        return parsed
    except subprocess.TimeoutExpired:
        log_warn("Whois timed out")
        return {}
    except Exception as e:
        log_error(f"Whois error: {e}")
        return {}


def run(domain, output_dir="output/json",
        record_types=None, skip_whois=False):
    os.makedirs(output_dir, exist_ok=True)

    if record_types is None:
        record_types = ["A","MX","TXT","NS","CNAME","AAAA","SOA"]

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"Target  : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Records : {', '.join(record_types)}")
    log_info(f"Whois   : {'Disabled' if skip_whois else 'Enabled'}")
    log_info(f"Output  : {output_dir}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    dns_records = {}
    for rtype in record_types:
        log_info(f"Fetching {rtype} records...")
        records = get_dns(domain, rtype)
        dns_records[rtype] = records
        if records:
            log_success(f"{rtype} → {len(records)} record(s)")
            for r in records: log_data(r)
        else:
            log_warn(f"{rtype} → No records found")

    whois_data = {}
    if not skip_whois:
        log_info("Running Whois lookup...")
        whois_data = get_whois(domain)
        if whois_data:
            log_success("Whois data collected:")
            for k, v in whois_data.items():
                log_data(f"{k}: {v}")
        else:
            log_warn("No Whois data found")

    data = {
        "module"      : "dns_whois",
        "domain"      : domain,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "record_types": record_types,
        "dns_records" : dns_records,
        "whois"       : whois_data
    }

    out_path = os.path.join(output_dir, "dns_whois.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success(f"DONE → Saved: {out_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args    = get_args()
    records = [r.strip() for r in args.records.split(",")]
    if not args.no_banner: banner()
    run(
        domain       = args.url,
        output_dir   = args.output,
        record_types = records,
        skip_whois   = args.no_whois
    )

