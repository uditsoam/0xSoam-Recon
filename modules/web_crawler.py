#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Web Crawler Module
#   Author  : Udit Soam
#   Usage   : python3 web_crawler.py -u target.com
#             python3 web_crawler.py -u target.com --tool gobuster
#             python3 web_crawler.py -u target.com --threads 100
#             python3 web_crawler.py -u target.com --wordlist /path/to/list.txt
#             python3 web_crawler.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.YELLOW}
 ██╗    ██╗███████╗██████╗      ██████╗██████╗  █████╗ ██╗    ██╗██╗
 ██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔══██╗██╔══██╗██║    ██║██║
 ██║ █╗ ██║█████╗  ██████╔╝    ██║     ██████╔╝███████║██║ █╗ ██║██║
 ██║███╗██║██╔══╝  ██╔══██╗    ██║     ██╔══██╗██╔══██║██║███╗██║██║
 ╚███╔███╔╝███████╗██████╔╝    ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗
  ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  [ Module 07 ] Web Crawler — Directory & Endpoint Discovery{Style.RESET_ALL}
{Fore.YELLOW}  Author: Udit Soam | 0xSoamRecon v1.0{Style.RESET_ALL}
{Fore.RED}  WARNING: Use only on authorized targets!{Style.RESET_ALL}
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def log_found(msg):   print(f"{Fore.GREEN}      [FOUND] {msg}{Style.RESET_ALL}")
def log_juicy(msg):   print(f"{Fore.RED}      [JUICY] {msg}{Style.RESET_ALL}")

# Interesting paths that signal high value findings
JUICY_PATHS = [
    "admin", "administrator", "login", "dashboard", "panel",
    "backup", "config", "db", "database", "secret", "private",
    "api", "swagger", "graphql", ".git", ".env", "wp-admin",
    "phpmyadmin", "upload", "uploads", "shell", "cmd", "console"
]

def get_args():
    parser = argparse.ArgumentParser(
        prog="web_crawler.py",
        description="0xSoamRecon — Web Directory & Endpoint Discovery",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 web_crawler.py -u target.com
  python3 web_crawler.py -u target.com --tool gobuster
  python3 web_crawler.py -u target.com --tool ffuf
  python3 web_crawler.py -u target.com --threads 100
  python3 web_crawler.py -u target.com --wordlist /usr/share/wordlists/dirbuster/medium.txt
  python3 web_crawler.py -u target.com --https
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain (e.g. target.com)"
    )
    parser.add_argument("--tool",
        default="both",
        choices=["gobuster", "ffuf", "both"],
        help="Tool to use (default: both)"
    )
    parser.add_argument("--threads",
        type=int, default=50,
        help="Number of threads (default: 50)"
    )
    parser.add_argument("--wordlist",
        default="/usr/share/wordlists/dirb/common.txt",
        help="Path to wordlist file"
    )
    parser.add_argument("--https",
        action="store_true",
        help="Force HTTPS (default: HTTP)"
    )
    parser.add_argument("--extensions",
        default="php,html,txt,bak,zip,js,json",
        help="File extensions to check (default: php,html,txt,bak,zip,js,json)"
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


def run_gobuster(url, wordlist, threads, extensions, timeout=300):
    log_info(f"Running Gobuster on {url}...")
    found = []
    try:
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-x", extensions,
            "--no-error",
            "-q"
        ]
        log_info(f"Command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=timeout
        )

        for line in result.stdout.split('\n'):
            line = line.strip()
            if line and "/" in line:
                # Parse gobuster output: /path (Status: 200) [Size: 1234]
                match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    path   = match.group(1)
                    status = int(match.group(2))
                    entry  = {
                        "path"  : path,
                        "status": status,
                        "tool"  : "gobuster",
                        "juicy" : any(j in path.lower() for j in JUICY_PATHS)
                    }
                    found.append(entry)
                    if entry["juicy"]:
                        log_juicy(f"{status} → {url}{path}")
                    elif status in [200, 201, 301, 302, 403]:
                        log_found(f"{status} → {url}{path}")

        log_success(f"Gobuster → {len(found)} paths found")
        return found

    except subprocess.TimeoutExpired:
        log_warn("Gobuster timed out")
        return found
    except FileNotFoundError:
        log_error("Gobuster not found → sudo apt install gobuster")
        return found
    except Exception as e:
        log_error(f"Gobuster error: {e}")
        return found


def run_ffuf(url, wordlist, threads, extensions, timeout=300):
    log_info(f"Running ffuf on {url}...")
    found = []
    try:
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-t", str(threads),
            "-e", f".{extensions.replace(',', ',.')}",
            "-mc", "200,201,301,302,403,405",
            "-of", "json",
            "-o", "/tmp/ffuf_0xsoamrecon.json",
            "-s"
        ]
        log_info(f"Command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=timeout
        )

        # Parse ffuf JSON output
        if os.path.exists("/tmp/ffuf_0xsoamrecon.json"):
            import json as _json
            with open("/tmp/ffuf_0xsoamrecon.json") as f:
                ffuf_data = _json.load(f)
            for r in ffuf_data.get("results", []):
                path  = "/" + r.get("input", {}).get("FUZZ", "")
                status = r.get("status", 0)
                entry  = {
                    "path"  : path,
                    "status": status,
                    "size"  : r.get("length", 0),
                    "tool"  : "ffuf",
                    "juicy" : any(j in path.lower() for j in JUICY_PATHS)
                }
                found.append(entry)
                if entry["juicy"]:
                    log_juicy(f"{status} → {url}{path}")
                else:
                    log_found(f"{status} → {url}{path}")
            os.remove("/tmp/ffuf_0xsoamrecon.json")

        log_success(f"ffuf → {len(found)} paths found")
        return found

    except subprocess.TimeoutExpired:
        log_warn("ffuf timed out")
        return found
    except FileNotFoundError:
        log_error("ffuf not found → sudo apt install ffuf")
        return found
    except Exception as e:
        log_error(f"ffuf error: {e}")
        return found


def run(domain, output_dir="output/json", tool="both",
        threads=50, wordlist="/usr/share/wordlists/dirb/common.txt",
        https=False, extensions="php,html,txt,bak,zip,js,json"):

    os.makedirs(output_dir, exist_ok=True)
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{domain}"

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    log_info(f"Target   : {Fore.GREEN}{base_url}{Style.RESET_ALL}")
    log_info(f"Tool     : {tool}")
    log_info(f"Wordlist : {wordlist}")
    log_info(f"Threads  : {threads}")
    log_info(f"Exts     : {extensions}")
    log_info(f"Output   : {output_dir}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")

    all_found = []

    if tool in ["gobuster", "both"]:
        gobuster_results = run_gobuster(
            base_url, wordlist, threads, extensions
        )
        all_found.extend(gobuster_results)

    if tool in ["ffuf", "both"]:
        ffuf_results = run_ffuf(
            base_url, wordlist, threads, extensions
        )
        all_found.extend(ffuf_results)

    # Deduplicate by path
    seen  = set()
    unique = []
    for item in all_found:
        if item["path"] not in seen:
            seen.add(item["path"])
            unique.append(item)

    juicy = [p for p in unique if p.get("juicy")]

    data = {
        "module"       : "web_crawler",
        "domain"       : domain,
        "base_url"     : base_url,
        "timestamp"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool_used"    : tool,
        "wordlist"     : wordlist,
        "total_found"  : len(unique),
        "juicy_paths"  : len(juicy),
        "results"      : unique
    }

    out_path = os.path.join(output_dir, "web_crawler.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n{Fore.WHITE}{'═'*60}{Style.RESET_ALL}")
    log_success(f"Crawl Complete — {len(unique)} unique paths found")
    if juicy:
        log_warn(f"{len(juicy)} JUICY paths found — check these first!")
        for j in juicy:
            log_juicy(f"{j['status']} → {base_url}{j['path']}")
    log_success(f"Saved → {out_path}")
    print(f"{Fore.WHITE}{'═'*60}{Style.RESET_ALL}\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner: banner()
    run(
        domain     = args.url,
        output_dir = args.output,
        tool       = args.tool,
        threads    = args.threads,
        wordlist   = args.wordlist,
        https      = args.https,
        extensions = args.extensions
    )
