#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Subdomain Enumeration Module
#   Author  : Udit Soam
#   Usage   : python3 subdomain_enum.py -u target.com
#             python3 subdomain_enum.py -u target.com -o /tmp/out
#             python3 subdomain_enum.py -u target.com --passive-only
#             python3 subdomain_enum.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, sys
from datetime import datetime
from colorama import Fore, Back, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
  ██╗   ██╗ ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║   ██║██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║   ██║██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ╚████╔╝ ╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 01 ] Subdomain Enumeration{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | 0xSoamRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)

def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.MAGENTA}      {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="subdomain_enum.py",
        description=f"0xSoamRecon — Subdomain Enumeration Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""
Examples:
  python3 subdomain_enum.py -u target.com
  python3 subdomain_enum.py -u target.com -o /tmp/results
  python3 subdomain_enum.py -u target.com --passive-only
  python3 subdomain_enum.py -u target.com --timeout 200
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
    parser.add_argument("--passive-only",
        action="store_true",
        help="Run Subfinder only — no Amass (faster, stealthier)"
    )
    parser.add_argument("--timeout",
        type=int, default=120,
        help="Timeout per tool in seconds (default: 120)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner output"
    )
    return parser.parse_args()


def run_subfinder(domain, timeout):
    log_info("Running Subfinder...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=timeout
        )
        found = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
        log_success(f"Subfinder → {len(found)} subdomains found")
        for s in found[:5]: log_data(s)
        if len(found) > 5: log_data(f"... and {len(found)-5} more")
        return found
    except subprocess.TimeoutExpired:
        log_warn("Subfinder timed out")
        return []
    except FileNotFoundError:
        log_error("Subfinder not installed → sudo apt install subfinder")
        return []
    except Exception as e:
        log_error(f"Subfinder error: {e}")
        return []


def run_amass(domain, timeout):
    log_info("Running Amass (passive mode)...")
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain],
            capture_output=True, text=True, timeout=timeout
        )
        found = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
        log_success(f"Amass → {len(found)} subdomains found")
        for s in found[:5]: log_data(s)
        if len(found) > 5: log_data(f"... and {len(found)-5} more")
        return found
    except subprocess.TimeoutExpired:
        log_warn("Amass timed out")
        return []
    except FileNotFoundError:
        log_error("Amass not installed → sudo apt install amass")
        return []
    except Exception as e:
        log_error(f"Amass error: {e}")
        return []


def run(domain, output_dir="output/json", passive_only=False, timeout=120):
    os.makedirs(output_dir, exist_ok=True)
    subdomains = set()

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"Target  : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Mode    : {'Passive Only (Subfinder)' if passive_only else 'Full (Subfinder + Amass)'}")
    log_info(f"Output  : {output_dir}")
    log_info(f"Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    subdomains.update(run_subfinder(domain, timeout))
    if not passive_only:
        subdomains.update(run_amass(domain, timeout))

    subdomains_list = sorted(list(subdomains))

    data = {
        "module"      : "subdomain_enum",
        "domain"      : domain,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode"        : "passive_only" if passive_only else "full",
        "total_found" : len(subdomains_list),
        "subdomains"  : subdomains_list
    }

    out_path = os.path.join(output_dir, "subdomain_enum.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success(f"DONE — Total subdomains: {Fore.YELLOW}{len(subdomains_list)}{Style.RESET_ALL}")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain       = args.url,
        output_dir   = args.output,
        passive_only = args.passive_only,
        timeout      = args.timeout
    )
