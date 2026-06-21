#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Shodan Intelligence Module
#   Author  : Udit Soam
#   Usage   : python3 shodan_lookup.py -u target.com
#             python3 shodan_lookup.py -u 192.168.1.1 --ip-mode
#             python3 shodan_lookup.py -u target.com --limit 50
#             python3 shodan_lookup.py --help
# ═══════════════════════════════════════════════════════════

import shodan, json, os, argparse, yaml
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.RED}
  ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗
  ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║
  ███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║
  ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║
  ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║
  ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 03 ] Shodan Intelligence — Exposed Services & CVEs{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | 0xSoamRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_vuln(msg):    print(f"{Fore.RED}  [VULN] {msg}{Style.RESET_ALL}")
def log_data(msg):    print(f"{Fore.BLUE}      → {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="shodan_lookup.py",
        description="0xSoamRecon — Shodan Intelligence Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 shodan_lookup.py -u target.com
  python3 shodan_lookup.py -u 192.168.1.1 --ip-mode
  python3 shodan_lookup.py -u target.com --limit 50
  python3 shodan_lookup.py -u target.com -o /tmp/results
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain or IP address"
    )
    parser.add_argument("--ip-mode",
        action="store_true",
        help="Target is an IP address — use host lookup instead of search"
    )
    parser.add_argument("--limit",
        type=int, default=20,
        help="Max results to fetch (default: 20)"
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


def load_api_key():
    try:
        with open("config/config.yaml", "r") as f:
            config = yaml.safe_load(f)
            key = config["shodan"]["api_key"]
            if key == "APNA_KEY_YAHAN_DAALO" or not key:
                return None
            return key
    except Exception as e:
        log_error(f"config.yaml read error: {e}")
        return None


def run(domain, output_dir="output/json", ip_mode=False, limit=20):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"Target  : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Mode    : {'IP Lookup' if ip_mode else 'Domain Search'}")
    log_info(f"Limit   : {limit}")
    log_info(f"Output  : {output_dir}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    api_key = load_api_key()
    if not api_key:
        log_error("No Shodan API key — add it to config/config.yaml")
        data = {
            "module"   : "shodan_lookup",
            "domain"   : domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error"    : "API key missing",
            "results"  : []
        }
        out_path = os.path.join(output_dir, "shodan_lookup.json")
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        return data

    api   = shodan.Shodan(api_key)
    hosts = []
    cve_summary = []

    try:
        if ip_mode:
            # Direct IP lookup
            log_info(f"Running Shodan host lookup on IP: {domain}")
            result = api.host(domain)
            host_info = {
                "ip"      : result.get("ip_str", domain),
                "org"     : result.get("org", "Unknown"),
                "os"      : result.get("os", "Unknown"),
                "country" : result.get("country_name", ""),
                "ports"   : result.get("ports", []),
                "cves"    : list(result.get("vulns", {}).keys()),
                "services": []
            }
            for item in result.get("data", []):
                host_info["services"].append({
                    "port"   : item.get("port", ""),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner" : item.get("data", "")[:150]
                })
            hosts.append(host_info)

            if host_info["cves"]:
                for cve in host_info["cves"]:
                    log_vuln(f"{host_info['ip']} → {cve}")
                    cve_summary.append(cve)
            else:
                log_success(f"{host_info['ip']} — {host_info['org']} — Ports: {host_info['ports']}")

        else:
            # Domain search
            log_info(f"Running Shodan search for: hostname:{domain}")
            results = api.search(f"hostname:{domain}")
            log_success(f"Shodan total results: {results['total']}")

            for result in results["matches"][:limit]:
                host_info = {
                    "ip"     : result.get("ip_str", ""),
                    "port"   : result.get("port", ""),
                    "org"    : result.get("org", "Unknown"),
                    "country": result.get("location", {}).get("country_name", ""),
                    "product": result.get("product", ""),
                    "version": result.get("version", ""),
                    "banner" : result.get("data", "")[:150],
                    "cves"   : list(result.get("vulns", {}).keys()),
                    "os"     : result.get("os", "Unknown")
                }
                hosts.append(host_info)

                if host_info["cves"]:
                    log_vuln(f"{host_info['ip']}:{host_info['port']} → CVEs: {host_info['cves']}")
                    cve_summary.extend(host_info["cves"])
                else:
                    log_data(f"{host_info['ip']}:{host_info['port']} — {host_info['product']} {host_info['version']}")

    except shodan.APIError as e:
        log_error(f"Shodan API Error: {e}")
        hosts = []

    data = {
        "module"      : "shodan_lookup",
        "domain"      : domain,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode"        : "ip" if ip_mode else "domain",
        "total"       : len(hosts),
        "cve_summary" : list(set(cve_summary)),
        "results"     : hosts
    }

    out_path = os.path.join(output_dir, "shodan_lookup.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success(f"DONE — {len(hosts)} hosts found")
    if cve_summary:
        log_warn(f"CVEs detected: {list(set(cve_summary))}")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain     = args.url,
        output_dir = args.output,
        ip_mode    = args.ip_mode,
        limit      = args.limit
    )
