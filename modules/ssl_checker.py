#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — SSL Certificate Checker Module
#   Author  : Udit Soam
#   Usage   : python3 ssl_checker.py -u target.com
#             python3 ssl_checker.py -u target.com --port 8443
#             python3 ssl_checker.py -u target.com --no-live
#             python3 ssl_checker.py --help
# ═══════════════════════════════════════════════════════════

import requests, subprocess, json, os, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.GREEN}
  ███████╗███████╗██╗
  ██╔════╝██╔════╝██║
  ███████╗███████╗██║
  ╚════██║╚════██║██║
  ███████║███████║███████╗
  ╚══════╝╚══════╝╚══════╝  CHECKER
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 05 ] SSL Certificate Analysis{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | 0xSoamRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.GREEN}      → {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="ssl_checker.py",
        description="0xSoamRecon — SSL Certificate Analysis Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 ssl_checker.py -u target.com
  python3 ssl_checker.py -u target.com --port 8443
  python3 ssl_checker.py -u target.com --no-live
  python3 ssl_checker.py -u target.com --limit 30
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("--port",
        type=int, default=443,
        help="SSL port to check (default: 443)"
    )
    parser.add_argument("--no-live",
        action="store_true",
        help="Skip live SSL connection check"
    )
    parser.add_argument("--limit",
        type=int, default=50,
        help="Max crt.sh results (default: 50)"
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


def check_crtsh(domain, limit):
    log_info("Querying crt.sh for certificate history...")
    try:
        url      = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=30)
        if response.status_code != 200:
            log_warn(f"crt.sh status: {response.status_code}")
            return []

        certs = response.json()
        seen  = set()
        result = []

        for cert in certs[:limit]:
            name = cert.get("name_value", "").strip()
            if name and name not in seen:
                seen.add(name)
                result.append({
                    "domain"    : name,
                    "issuer"    : cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after" : cert.get("not_after", ""),
                    "serial"    : cert.get("serial_number", "")
                })

        log_success(f"crt.sh → {len(result)} unique certificates found")
        for c in result[:5]: log_data(c["domain"])
        if len(result) > 5: log_data(f"... and {len(result)-5} more")
        return result

    except Exception as e:
        log_error(f"crt.sh error: {e}")
        return []


def live_ssl_check(domain, port, timeout=15):
    log_info(f"Checking live SSL on {domain}:{port}...")
    ssl_info = {}
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect",
             f"{domain}:{port}", "-servername", domain],
            input="Q\n", capture_output=True,
            text=True, timeout=timeout
        )
        output = result.stdout + result.stderr

        ssl_info["connected"] = "CONNECTED" in output

        for line in output.split('\n'):
            l = line.strip()
            if "subject=" in l.lower():
                ssl_info["subject"] = l
            if "issuer=" in l.lower():
                ssl_info["issuer"] = l
            if "notafter" in l.lower() or "not after" in l.lower():
                ssl_info["expiry"] = l
            if "notbefore" in l.lower() or "not before" in l.lower():
                ssl_info["valid_from"] = l
            if "SSL-Session" in l:
                break

        if ssl_info.get("connected"):
            log_success("Live SSL connection successful")
        else:
            log_warn("SSL connection failed or no SSL on this port")

    except subprocess.TimeoutExpired:
        log_warn("Live SSL check timed out")
        ssl_info["connected"] = False
    except Exception as e:
        log_error(f"Live SSL error: {e}")
        ssl_info["error"] = str(e)

    return ssl_info


def run(domain, output_dir="output/json",
        port=443, skip_live=False, limit=50):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"Target  : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Port    : {port}")
    log_info(f"Live SSL: {'Disabled' if skip_live else 'Enabled'}")
    log_info(f"Limit   : {limit} crt.sh results")
    log_info(f"Output  : {output_dir}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    cert_history = check_crtsh(domain, limit)
    live_ssl     = {} if skip_live else live_ssl_check(domain, port)

    data = {
        "module"       : "ssl_checker",
        "domain"       : domain,
        "timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "port_checked" : port,
        "total_certs"  : len(cert_history),
        "cert_history" : cert_history,
        "live_ssl"     : live_ssl
    }

    out_path = os.path.join(output_dir, "ssl_checker.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success(f"DONE — {len(cert_history)} certs found")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain     = args.url,
        output_dir = args.output,
        port       = args.port,
        skip_live  = args.no_live,
        limit      = args.limit
    )
