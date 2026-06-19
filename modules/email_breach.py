#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — Email Breach Check Module
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/VoidRecon
#   Usage   : python3 email_breach.py -u target.com
#             python3 email_breach.py -u target.com --emails a@b.com,c@d.com
#             python3 email_breach.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse, requests, time, yaml
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[91m
 ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
 ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
 ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
 ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  CHECK
\033[0m
\033[97m  [ Module 14 ] Email Breach Check — HaveIBeenPwned\033[0m
\033[93m  Author: Udit Soam | VoidRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_breach(msg):  print(f"{Fore.RED}  [BREACH] {msg}{Style.RESET_ALL}")
def log_clean(msg):   print(f"{Fore.GREEN}  [CLEAN] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      → {msg}{Style.RESET_ALL}")


def get_args():
    parser = argparse.ArgumentParser(
        prog="email_breach.py",
        description="VoidRecon — Email Breach Check via HaveIBeenPwned",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 email_breach.py -u target.com
  python3 email_breach.py -u target.com --emails user@target.com,admin@target.com
  python3 email_breach.py -u target.com -o /tmp/results
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
    parser.add_argument("--emails",
        default=None,
        help="Comma-separated emails to check (overrides osint_harvest.json)"
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
        key = config.get("haveibeenpwned", {}).get("api_key", "")
        if not key or key == "USER_HIBP_KEY":
            return None
        return key
    except Exception as e:
        log_error(f"config.yaml error: {e}")
        return None


def load_emails_from_osint(output_dir):
    osint_file = os.path.join(output_dir, "osint_harvest.json")
    if not os.path.exists(osint_file):
        log_warn("osint_harvest.json not found")
        return []
    try:
        with open(osint_file) as f:
            data = json.load(f)
        emails = data.get("emails", [])
        log_success(f"Loaded {len(emails)} emails from osint_harvest.json")
        return emails
    except Exception as e:
        log_error(f"Could not read osint_harvest.json: {e}")
        return []


def check_email_hibp(email, api_key):
    headers = {
        "User-Agent"  : "VoidRecon/1.0",
        "hibp-api-key": api_key
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    try:
        resp = requests.get(
            url,
            headers = headers,
            params  = {"truncateResponse": "false"},
            timeout = 15
        )

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return []
        elif resp.status_code == 401:
            log_error("HIBP API key invalid or missing")
            return None
        elif resp.status_code == 429:
            log_warn("HIBP rate limit — waiting 2 seconds")
            time.sleep(2)
            return check_email_hibp(email, api_key)
        else:
            log_warn(f"HIBP returned: {resp.status_code}")
            return []

    except Exception as e:
        log_error(f"HIBP check error for {email}: {e}")
        return []


def check_email_no_key(email):
    # Free endpoint — domain level only
    domain = email.split("@")[-1] if "@" in email else email
    url    = f"https://haveibeenpwned.com/api/v3/breaches"

    try:
        resp = requests.get(
            url,
            headers = {"User-Agent": "VoidRecon/1.0"},
            timeout = 15
        )
        if resp.status_code == 200:
            all_breaches = resp.json()
            log_warn(f"No API key — showing public breach list only")
            return all_breaches[:3]
        return []
    except Exception:
        return []


def parse_breach(breach):
    return {
        "name"         : breach.get("Name", ""),
        "domain"       : breach.get("Domain", ""),
        "breach_date"  : breach.get("BreachDate", ""),
        "pwn_count"    : breach.get("PwnCount", 0),
        "data_classes" : breach.get("DataClasses", []),
        "description"  : breach.get("Description", "")[:200],
        "is_sensitive" : breach.get("IsSensitive", False),
        "is_verified"  : breach.get("IsVerified", False)
    }


def run(domain, output_dir="output/json",
        manual_emails=None):

    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_info(f"Target   : {domain}")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'═'*60}\033[0m\n")

    # Load API key
    api_key = load_api_key()
    if not api_key:
        log_warn("No HIBP API key found in config.yaml")
        log_warn("Get free key: haveibeenpwned.com/API")
        log_warn("Running in limited mode...")
    else:
        log_success("HIBP API key loaded")

    # Load emails
    if manual_emails:
        emails = [e.strip() for e in manual_emails.split(",")]
        log_success(f"Using {len(emails)} manually provided emails")
    else:
        emails = load_emails_from_osint(output_dir)

    if not emails:
        log_warn("No emails to check")
        data = {
            "module"          : "email_breach",
            "domain"          : domain,
            "timestamp"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_checked"   : 0,
            "total_breached"  : 0,
            "breached_emails" : [],
            "clean_emails"    : []
        }
        out_path = os.path.join(output_dir, "email_breach.json")
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return data

    log_info(f"Checking {len(emails)} emails against HIBP...")
    print()

    breached_emails = []
    clean_emails    = []
    failed_emails   = []

    for i, email in enumerate(emails, 1):
        log_info(f"[{i}/{len(emails)}] Checking: {email}")

        if api_key:
            result = check_email_hibp(email, api_key)
        else:
            result = check_email_no_key(email)

        if result is None:
            log_error(f"API key invalid — stopping checks")
            failed_emails.append(email)
            break

        if result:
            breaches = [parse_breach(b) for b in result]
            entry    = {
                "email"          : email,
                "breach_count"   : len(breaches),
                "breaches"       : breaches,
                "sensitive_count": sum(
                    1 for b in breaches if b.get("is_sensitive")
                ),
                "data_types"     : list(set(
                    dt for b in breaches
                    for dt in b.get("data_classes", [])
                ))
            }
            breached_emails.append(entry)

            log_breach(
                f"{email} — found in {len(breaches)} breach(es)!"
            )
            for b in breaches[:3]:
                log_data(
                    f"{b['name']} ({b['breach_date']}) — "
                    f"{b['pwn_count']:,} accounts — "
                    f"{', '.join(b['data_classes'][:3])}"
                )
        else:
            clean_emails.append(email)
            log_clean(f"{email} — Not found in any breach")

        # Rate limit — 1.5 seconds between requests
        time.sleep(1.5)

    data = {
        "module"          : "email_breach",
        "domain"          : domain,
        "timestamp"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_checked"   : len(emails),
        "total_breached"  : len(breached_emails),
        "total_clean"     : len(clean_emails),
        "total_failed"    : len(failed_emails),
        "breached_emails" : breached_emails,
        "clean_emails"    : clean_emails,
        "failed_emails"   : failed_emails
    }

    out_path = os.path.join(output_dir, "email_breach.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'═'*60}\033[0m")
    log_success(f"Email Breach Check Complete")
    log_success(f"Checked  : {len(emails)}")
    if breached_emails:
        log_breach(f"Breached : {len(breached_emails)} emails found in breaches!")
    else:
        log_clean(f"Breached : 0 — No breaches found")
    log_success(f"Clean    : {len(clean_emails)}")
    log_success(f"Saved → {out_path}")
    print(f"\033[97m{'═'*60}\033[0m\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner:
        banner()

    manual = None
    if args.emails:
        manual = args.emails

    run(
        domain        = args.url,
        output_dir    = args.output,
        manual_emails = manual
    )
