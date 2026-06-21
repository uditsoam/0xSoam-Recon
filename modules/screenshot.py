#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Web Screenshot Module
#   Author  : Udit Soam
#   Usage   : python3 screenshot.py -u target.com
#             python3 screenshot.py -u target.com --subdomains subs.txt
#             python3 screenshot.py -u target.com --threads 5
#             python3 screenshot.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.GREEN}
 ███████╗ ██████╗██████╗ ███████╗███████╗███╗   ██╗
 ██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║
 ███████╗██║     ██████╔╝█████╗  █████╗  ██╔██╗ ██║
 ╚════██║██║     ██╔══██╗██╔══╝  ██╔══╝  ██║╚██╗██║
 ███████║╚██████╗██║  ██║███████╗███████╗██║ ╚████║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝  SHOT
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 09 ] Web Screenshot Capture{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | 0xSoamRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_shot(msg):    print(f"{Fore.GREEN}      [SHOT] {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="screenshot.py",
        description="0xSoamRecon — Web Screenshot Capture Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 screenshot.py -u target.com
  python3 screenshot.py -u target.com --subdomains output/json/subdomain_enum.json
  python3 screenshot.py -u target.com --threads 5
  python3 screenshot.py -u target.com --both-protocols
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("--subdomains",
        default=None,
        help="Path to subdomain_enum.json to screenshot all subdomains"
    )
    parser.add_argument("--threads",
        type=int, default=3,
        help="Number of parallel threads (default: 3)"
    )
    parser.add_argument("--both-protocols",
        action="store_true",
        help="Screenshot both HTTP and HTTPS"
    )
    parser.add_argument("-o", "--output",
        default="output",
        help="Base output directory (default: output)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def build_url_list(domain, subdomains_json, both_protocols):
    urls = []
    protocols = ["http", "https"] if both_protocols else ["http"]

    # Always add main domain
    for proto in protocols:
        urls.append(f"{proto}://{domain}")

    # Add subdomains if provided
    if subdomains_json and os.path.exists(subdomains_json):
        log_info(f"Loading subdomains from: {subdomains_json}")
        try:
            import json as _json
            with open(subdomains_json) as f:
                data = _json.load(f)
            subs = data.get("subdomains", [])
            for sub in subs[:30]:  # limit to 30
                for proto in protocols:
                    urls.append(f"{proto}://{sub}")
            log_success(f"Added {len(subs)} subdomains to screenshot list")
        except Exception as e:
            log_error(f"Could not load subdomains: {e}")

    return list(set(urls))


def run_eyewitness(urls, screenshot_dir, threads):
    log_info(f"Running EyeWitness on {len(urls)} URL(s)...")

    # Write URLs to temp file
    url_file = "/tmp/0xsoamrecon_urls.txt"
    with open(url_file, "w") as f:
        f.write('\n'.join(urls))

    try:
        cmd = [
            "eyewitness",
            "--web",
            "-f", url_file,
            "-d", screenshot_dir,
            "--no-prompt",
            "--threads", str(threads),
            "--timeout", "10"
        ]
        log_info(f"Command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=300
        )

        captured = []
        failed   = []

        for line in result.stdout.split('\n'):
            if "Attempting to screenshot" in line:
                url = line.split("Attempting to screenshot")[-1].strip()
                log_shot(url)
                captured.append(url)
            elif "Timed out" in line or "Error" in line:
                failed.append(line.strip())

        log_success(f"EyeWitness → {len(captured)} screenshots captured")
        if failed:
            log_warn(f"{len(failed)} URLs failed")

        return captured, failed

    except subprocess.TimeoutExpired:
        log_warn("EyeWitness timed out")
        return [], urls
    except FileNotFoundError:
        log_warn("EyeWitness not found — trying fallback method")
        return [], urls
    except Exception as e:
        log_error(f"EyeWitness error: {e}")
        return [], urls


def fallback_curl_check(urls):
    """Fallback when EyeWitness unavailable — at least verify which URLs are live"""
    log_info("Fallback: Checking which URLs are live with curl...")
    live = []
    dead = []

    for url in urls:
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "8", "-L", url],
                capture_output=True, text=True, timeout=12
            )
            status = result.stdout.strip()
            if status and status.isdigit() and int(status) < 500:
                log_shot(f"{status} → {url}")
                live.append({"url": url, "status": int(status)})
            else:
                dead.append(url)
        except Exception:
            dead.append(url)

    log_success(f"Live URLs: {len(live)} | Dead/Unreachable: {len(dead)}")
    return live, dead


def run(domain, output_dir="output", subdomains_json=None,
        threads=3, both_protocols=False):

    screenshot_dir = os.path.join(output_dir, "screenshots", domain)
    json_dir       = os.path.join(output_dir, "json")
    os.makedirs(screenshot_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    log_info(f"Target     : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    log_info(f"Protocols  : {'HTTP + HTTPS' if both_protocols else 'HTTP only'}")
    log_info(f"Subdomains : {subdomains_json if subdomains_json else 'Main domain only'}")
    log_info(f"Threads    : {threads}")
    log_info(f"Screenshots: {screenshot_dir}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")

    urls      = build_url_list(domain, subdomains_json, both_protocols)
    log_info(f"Total URLs to screenshot: {len(urls)}")

    captured, failed = run_eyewitness(urls, screenshot_dir, threads)

    # Fallback if EyeWitness got nothing
    live_urls = []
    if not captured:
        live_urls, dead_urls = fallback_curl_check(urls)

    data = {
        "module"          : "screenshot",
        "domain"          : domain,
        "timestamp"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_urls"      : len(urls),
        "urls_targeted"   : urls,
        "captured"        : captured,
        "failed"          : failed,
        "screenshot_dir"  : screenshot_dir,
        "live_urls"       : live_urls
    }

    out_path = os.path.join(json_dir, "screenshot.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    log_success(f"Screenshots saved in: {screenshot_dir}")
    log_success(f"Captured: {len(captured)} | Failed: {len(failed)}")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain          = args.url,
        output_dir      = args.output,
        subdomains_json = args.subdomains,
        threads         = args.threads,
        both_protocols  = args.both_protocols
    )
