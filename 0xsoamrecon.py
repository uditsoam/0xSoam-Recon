#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Main Orchestrator v2.0
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
# ═══════════════════════════════════════════════════════════

import os, sys, time, json, yaml, argparse
from datetime import datetime
from colorama import Fore, Back, Style, init
init(autoreset=True)

C  = Fore.CYAN
G  = Fore.GREEN
Y  = Fore.YELLOW
R  = Fore.RED
W  = Fore.WHITE
M  = Fore.MAGENTA
B  = Fore.BLUE
RS = Style.RESET_ALL
BB = Back.BLUE

BANNER = """
\033[96m
 ██╗   ██╗ ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║   ██║██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║   ██║██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
\033[97m         Automated Red Team Reconnaissance Framework v2.0\033[0m
\033[93m         Author : Udit Soam  |  github.com/uditsoam/0xSoamRecon\033[0m
\033[91m         WARNING: Use only on authorized targets!\033[0m
"""

MODULES = {
    1 : {"name": "Subdomain Enumeration",    "file": "subdomain_enum",  "group": 1, "default": True,  "tool": "Amass + Subfinder"  },
    2 : {"name": "OSINT Harvesting",         "file": "osint_harvest",   "group": 1, "default": True,  "tool": "theHarvester"       },
    3 : {"name": "Shodan Intelligence",      "file": "shodan_lookup",   "group": 1, "default": True,  "tool": "Shodan API"         },
    4 : {"name": "DNS & Whois Analysis",     "file": "dns_whois",       "group": 1, "default": True,  "tool": "dig + whois"        },
    5 : {"name": "SSL Certificate History",  "file": "ssl_checker",     "group": 1, "default": True,  "tool": "crt.sh"             },
    6 : {"name": "Port Scanner",             "file": "port_scanner",    "group": 2, "default": True,  "tool": "Nmap"               },
    7 : {"name": "Web Directory Crawler",    "file": "web_crawler",     "group": 2, "default": True,  "tool": "Gobuster + ffuf"    },
    8 : {"name": "HTTP Header Analysis",     "file": "http_headers",    "group": 2, "default": True,  "tool": "curl + Nikto"       },
    9 : {"name": "Web Screenshots",          "file": "screenshot",      "group": 2, "default": True,  "tool": "EyeWitness"         },
    10: {"name": "Tech Stack Fingerprint",   "file": "tech_stack",      "group": 3, "default": False, "tool": "WhatWeb"            },
    11: {"name": "Subdomain Takeover Check", "file": "takeover_check",  "group": 3, "default": False, "tool": "DNS + HTTP"         },
    12: {"name": "GitHub Dorking",           "file": "github_dork",     "group": 3, "default": False, "tool": "GitHub API"         },
    13: {"name": "Wayback Machine URLs",     "file": "wayback",         "group": 3, "default": False, "tool": "archive.org"        },
    14: {"name": "Email Breach Check",       "file": "email_breach",    "group": 4, "default": False, "tool": "HaveIBeenPwned"     },
    15: {"name": "CVE Auto Lookup",          "file": "cve_lookup",      "group": 4, "default": False, "tool": "NVD API"            },
    16: {"name": "Google Dork Generator",    "file": "dork_generator",  "group": 4, "default": False, "tool": "Auto Generate"      },
    17: {"name": "Risk Score Calculator",    "file": None,              "group": 5, "default": True,  "tool": "0-100 Scoring"      },
    18: {"name": "Recommendations Engine",   "file": None,              "group": 5, "default": True,  "tool": "Auto Suggestions"   },
    19: {"name": "PDF + HTML Report",        "file": None,              "group": 5, "default": True,  "tool": "WeasyPrint"         },
    20: {"name": "Scan History Log",         "file": "scan_history",    "group": 5, "default": True,  "tool": "Local JSON DB"      },
}

GROUPS = {
    1: {"name": "PASSIVE INTEL",     "default": "ON",        "color": "\033[96m"},
    2: {"name": "ACTIVE RECON",      "default": "ON",        "color": "\033[92m"},
    3: {"name": "ADVANCED INTEL",    "default": "SUGGESTED", "color": "\033[93m"},
    4: {"name": "OSINT EXTRAS",      "default": "SUGGESTED", "color": "\033[95m"},
    5: {"name": "REPORT & ANALYSIS", "default": "ON",        "color": "\033[94m"},
}

PRESETS = {
    "A": list(range(1, 21)),
    "P": [1, 2, 3, 4, 5, 17, 18, 19, 20],
    "Q": [1, 4, 6, 8, 17, 19],
}


def log_info(msg):    print(f"\033[96m[*] {msg}\033[0m")
def log_success(msg): print(f"\033[92m[+] {msg}\033[0m")
def log_warn(msg):    print(f"\033[93m[!] {msg}\033[0m")
def log_error(msg):   print(f"\033[91m[-] {msg}\033[0m")
def log_phase(msg):   print(f"\n\033[97m\033[44m {msg} \033[0m\n")
def log_skip(msg):    print(f"\033[97m[~] SKIPPED: {msg}\033[0m")


def clear_screen():
    os.system("clear")


def load_config():
    try:
        with open("config/config.yaml") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def save_config(config):
    try:
        with open("config/config.yaml", "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception as e:
        log_error(f"Could not save config: {e}")


def needs_setup():
    config = load_config()
    shodan = config.get("shodan", {}).get("api_key", "")
    return not shodan or shodan == "USER_SHODAN_KEY"


def first_time_setup():
    config  = load_config()
    changed = False

    print(f"\n\033[93m{'='*62}\033[0m")
    print(f"\033[93m  0xSoamRecon — First Time Setup\033[0m")
    print(f"\033[93m{'='*62}\033[0m")
    print(f"\033[97m  Some modules need API keys to work.\033[0m")
    print(f"\033[97m  Press ENTER to skip any key.\033[0m\n")

    keys_config = [
        ("Shodan API Key",        "shodan",          "api_key",  "USER_SHODAN_KEY",   "shodan.io"),
        ("GitHub Token",          "github",          "token",    "USER_GITHUB_TOKEN",  "github.com/settings/tokens"),
        ("HaveIBeenPwned Key",    "haveibeenpwned",  "api_key",  "USER_HIBP_KEY",      "haveibeenpwned.com/API"),
        ("NVD API Key",           "nvd",             "api_key",  "USER_NVD_KEY",       "nvd.nist.gov/developers"),
    ]

    for label, section, field, placeholder, url in keys_config:
        current = config.get(section, {}).get(field, "")
        if not current or current == placeholder:
            print(f"\033[96m  {label}\033[0m")
            print(f"  Get free key: \033[97m{url}\033[0m")
            key = input(f"  Enter {label}: ").strip()
            if key:
                if section not in config:
                    config[section] = {}
                config[section][field] = key
                changed = True
                log_success(f"{label} saved")
            else:
                log_warn(f"{label} skipped")
            print()

    if changed:
        save_config(config)
        log_success("Configuration saved to config/config.yaml")

    print(f"\033[93m{'='*62}\033[0m\n")
    input(f"  \033[97mPress ENTER to continue...\033[0m")


def draw_ui(selected, domain):
    clear_screen()
    print(BANNER)

    print(f"\033[97m\u2554{'═'*62}\u2557\033[0m")
    print(f"\033[97m\u2551\033[0m  \033[96mTarget:\033[0m \033[92m{domain:<53}\033[0m\033[97m\u2551\033[0m")
    print(f"\033[97m\u2560{'═'*62}\u2563\033[0m")

    current_group = 0
    for num, mod in MODULES.items():
        grp = mod["group"]

        if grp != current_group:
            current_group = grp
            g_info  = GROUPS[grp]
            g_name  = g_info["name"]
            g_def   = g_info["default"]
            g_color = g_info["color"]
            def_color = "\033[92m" if g_def == "ON" else "\033[93m"

            print(f"\033[97m\u2551\033[0m")
            line = f"  {g_color}{g_name:<30}\033[0m  [{def_color}{g_def}\033[0m]"
            pad  = 62 - 2 - len(g_name) - 4 - len(g_def) - 2
            print(f"\033[97m\u2551\033[0m{line}{' '*max(0,pad)}\033[97m\u2551\033[0m")
            print(f"\033[97m\u2551  {'─'*58}\u2551\033[0m")

        is_on    = num in selected
        checkbox = "\033[92m✅\033[0m" if is_on else "⬜"
        name     = mod["name"]
        tool     = mod["tool"]
        num_str  = f"{num:02d}"

        name_pad = 28 - len(name)
        tool_pad = 20 - len(tool)

        line = (
            f"  [{'\033[93m'}{num_str}{'\033[0m'}] {checkbox}  "
            f"{name}{' '*max(0,name_pad)}"
            f"\033[94m{tool}\033[0m{' '*max(0,tool_pad)}"
        )
        print(f"\033[97m\u2551\033[0m{line}\033[97m\u2551\033[0m")

    print(f"\033[97m\u2551\033[0m")
    print(f"\033[97m\u2560{'═'*62}\u2563\033[0m")
    preset_line = (
        f"  \033[92m[A]\033[0m All Modules  "
        f"\033[96m[P]\033[0m Passive Only  "
        f"\033[93m[Q]\033[0m Quick Scan              "
    )
    print(f"\033[97m\u2551\033[0m{preset_line}\033[97m\u2551\033[0m")
    print(f"\033[97m\u2560{'═'*62}\u2563\033[0m")

    toggle_line = f"  Toggle: type numbers \033[93m(e.g: 10,12,15)\033[0m to enable/disable      "
    enter_line  = f"  Press \033[92mENTER\033[0m with no input to \033[92mSTART SCAN\033[0m                    "
    help_line   = f"  Type \033[96mHELP\033[0m for reference  Type \033[91mEXIT\033[0m to quit             "

    print(f"\033[97m\u2551\033[0m{toggle_line}\033[97m\u2551\033[0m")
    print(f"\033[97m\u2551\033[0m{enter_line}\033[97m\u2551\033[0m")
    print(f"\033[97m\u2551\033[0m{help_line}\033[97m\u2551\033[0m")
    print(f"\033[97m\u255a{'═'*62}\u255d\033[0m")

    active  = len(selected)
    passive = len([s for s in selected if MODULES[s]["group"] == 1])
    active_c = len([s for s in selected if MODULES[s]["group"] == 2])
    adv     = len([s for s in selected if MODULES[s]["group"] in [3, 4]])
    print(
        f"\n  \033[97mSelected: \033[92m{active}\033[0m\033[97m/20\033[0m"
        f"  Passive: \033[92m{passive}\033[0m"
        f"  Active: \033[92m{active_c}\033[0m"
        f"  Advanced: \033[93m{adv}\033[0m"
    )


def show_help():
    clear_screen()
    print(f"\n\033[96m{'='*60}\033[0m")
    print(f"\033[97m  0xSoamRecon — Help Reference\033[0m")
    print(f"\033[96m{'='*60}\033[0m\n")
    print(f"\033[93m  INTERACTIVE CONTROLS:\033[0m")
    print(f"  \033[97mNumber(s)\033[0m  : Toggle module ON/OFF (e.g: 10 or 10,12,15)")
    print(f"  \033[92mA\033[0m          : Select ALL 20 modules")
    print(f"  \033[96mP\033[0m          : Passive Only (1-5 + report)")
    print(f"  \033[93mQ\033[0m          : Quick scan (1,4,6,8 + report)")
    print(f"  \033[92mENTER\033[0m      : Start scan with selected modules")
    print(f"  \033[91mEXIT\033[0m       : Quit 0xSoamRecon\n")
    print(f"\033[93m  CLI FLAGS:\033[0m")
    print(f"  \033[96m-u / --url\033[0m        : Target domain or IP")
    print(f"  \033[96m-o / --output\033[0m     : Output directory")
    print(f"  \033[96m--speed\033[0m           : Nmap speed T1-T5 (default T4)")
    print(f"  \033[96m--top-ports\033[0m       : Nmap top ports (default 1000)")
    print(f"  \033[96m--threads\033[0m         : Web crawl threads (default 50)")
    print(f"  \033[96m--https\033[0m           : Force HTTPS")
    print(f"  \033[96m--no-interactive\033[0m  : Run default modules, skip selector")
    print(f"  \033[96m--history\033[0m         : Show scan history and exit\n")
    print(f"\033[93m  SAFE TEST TARGETS:\033[0m")
    print(f"  \033[92mtestphp.vulnweb.com\033[0m  : Acunetix vulnerable test site")
    print(f"  \033[92mscanme.nmap.org\033[0m      : Official Nmap test target\n")
    print(f"\033[96m{'='*60}\033[0m")
    input(f"\n  \033[97mPress ENTER to go back...\033[0m")


def confirm_scan(selected, domain, args):
    clear_screen()
    print(f"\n\033[97m{'='*60}\033[0m")
    print(f"\033[92m  0xSoamRecon — Scan Confirmation\033[0m")
    print(f"\033[97m{'='*60}\033[0m\n")
    print(f"  \033[96mTarget    :\033[0m \033[92m{domain}\033[0m")
    print(f"  \033[96mOutput    :\033[0m {args.output}")
    print(f"  \033[96mSpeed     :\033[0m {args.speed}")
    print(f"  \033[96mModules   :\033[0m {len(selected)} selected\n")

    for grp_num, grp_info in GROUPS.items():
        mods_in_grp = [m for m in selected if MODULES[m]["group"] == grp_num]
        if mods_in_grp:
            color = grp_info["color"]
            print(f"  {color}{grp_info['name']}\033[0m:")
            for m in mods_in_grp:
                print(f"    \033[92m✅\033[0m [{m:02d}] {MODULES[m]['name']}")
            print()

    passive_count = len([s for s in selected if MODULES[s]["group"] == 1])
    active_count  = len([s for s in selected if MODULES[s]["group"] == 2])
    adv_count     = len([s for s in selected if MODULES[s]["group"] in [3, 4]])
    est_min = (passive_count * 1.5) + (active_count * 3) + (adv_count * 2)
    est_max = est_min * 1.8

    print(f"  \033[93mEstimated time: {int(est_min)}-{int(est_max)} minutes\033[0m\n")
    print(f"\033[97m{'='*60}\033[0m")

    confirm = input(f"\n  Start scan? \033[92m(Y/n)\033[0m: ").strip().lower()
    return confirm in ["", "y", "yes"]


def interactive_selector(domain):
    selected = set(num for num, mod in MODULES.items() if mod["default"])

    while True:
        draw_ui(selected, domain)

        try:
            user_input = input(f"\n  \033[93mSelection:\033[0m ").strip().upper()
        except KeyboardInterrupt:
            print(f"\n\033[93m  Interrupted\033[0m")
            sys.exit(0)

        if not user_input:
            return sorted(list(selected))

        elif user_input == "EXIT":
            print(f"\n\033[93m  Goodbye!\033[0m")
            sys.exit(0)

        elif user_input == "HELP":
            show_help()

        elif user_input == "A":
            selected = set(range(1, 21))
            log_success("All 20 modules selected")
            time.sleep(0.5)

        elif user_input == "P":
            selected = set(PRESETS["P"])
            log_success("Passive Only preset selected")
            time.sleep(0.5)

        elif user_input == "Q":
            selected = set(PRESETS["Q"])
            log_success("Quick Scan preset selected")
            time.sleep(0.5)

        else:
            try:
                nums = [int(x.strip()) for x in user_input.split(",") if x.strip().isdigit()]
                for num in nums:
                    if 1 <= num <= 20:
                        if num in selected:
                            selected.discard(num)
                            log_warn(f"Module {num:02d} — {MODULES[num]['name']} — OFF")
                        else:
                            selected.add(num)
                            log_success(f"Module {num:02d} — {MODULES[num]['name']} — ON")
                    else:
                        log_warn(f"Invalid module: {num} (1-20 only)")
                time.sleep(0.6)
            except ValueError:
                log_warn("Invalid input — enter numbers like: 10,12,15")
                time.sleep(0.8)


def run_module_safe(name, func):
    log_info(f"Running: {name}")
    start = time.time()
    try:
        result  = func()
        elapsed = round(time.time() - start, 1)
        log_success(f"{name} completed in {elapsed}s")
        return result or {}
    except Exception as e:
        log_error(f"{name} failed: {e}")
        return {}


def print_final_summary(merged, domain, elapsed_total, selected):
    s = merged.get("summary", {})
    print(f"\n\033[96m{'='*65}\033[0m")
    print(f"\033[92m  0XSOAMRECON SCAN COMPLETE\033[0m")
    print(f"\033[96m{'='*65}\033[0m\n")
    print(f"  \033[97mTARGET\033[0m          : \033[92m{domain}\033[0m")
    print(f"  \033[97mCOMPLETED\033[0m       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  \033[97mTOTAL TIME\033[0m      : {elapsed_total}s")
    print(f"  \033[97mMODULES RUN\033[0m     : {len(selected)}/20")
    print(f"\n\033[96m  {'─'*60}\033[0m")
    print(f"  \033[96mSUBDOMAINS\033[0m      : \033[93m{s.get('total_subdomains',0)}\033[0m")
    print(f"  \033[96mEMAILS\033[0m          : \033[93m{s.get('total_emails',0)}\033[0m")
    print(f"  \033[96mOPEN PORTS\033[0m      : \033[93m{s.get('total_open_ports',0)}\033[0m  (\033[91m{s.get('high_risk_ports',0)} HIGH\033[0m)")
    print(f"  \033[96mWEB PATHS\033[0m       : \033[93m{s.get('total_web_paths',0)}\033[0m  (\033[91m{s.get('juicy_paths',0)} JUICY\033[0m)")
    print(f"  \033[96mSSL CERTS\033[0m       : \033[93m{s.get('total_certs',0)}\033[0m")
    print(f"  \033[96mSHODAN\033[0m          : \033[93m{s.get('shodan_results',0)}\033[0m")

    grade = s.get("security_grade", "N/A")
    gc    = "\033[92m" if grade in ["A","B"] else "\033[93m" if grade == "C" else "\033[91m"
    print(f"  \033[96mSECURITY GRADE\033[0m  : {gc}{grade}\033[0m")

    rs = s.get("risk_score", "N/A")
    rg = s.get("risk_grade", "N/A")
    if rs != "N/A":
        rc = "\033[92m" if int(str(rs)) >= 75 else "\033[93m" if int(str(rs)) >= 50 else "\033[91m"
        print(f"  \033[96mRISK SCORE\033[0m      : {rc}{rs}/100 ({rg})\033[0m")

    cves = s.get("cves_detected", [])
    if cves:
        print(f"\n  \033[91m[!!!] CVEs DETECTED: {cves}\033[0m")

    print(f"\n\033[96m  {'─'*60}\033[0m")
    print(f"  \033[92mReports : output/reports/\033[0m")
    print(f"  \033[92mJSON    : output/json/recon_report.json\033[0m")
    print(f"\033[96m{'='*65}\033[0m\n")


def get_args():
    parser = argparse.ArgumentParser(
        prog="0xsoamrecon.py",
        description="0xSoamRecon — Automated Red Team Reconnaissance Framework v2.0",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 0xsoamrecon.py -u target.com
  python3 0xsoamrecon.py -u target.com --no-interactive
  python3 0xsoamrecon.py -u target.com --speed T3 --top-ports 500
  python3 0xsoamrecon.py --history
        """
    )
    parser.add_argument("-u", "--url",      default=None,  help="Target domain or IP")
    parser.add_argument("-o", "--output",   default="output", help="Output directory (default: output)")
    parser.add_argument("--speed",          default="T4",  choices=["T1","T2","T3","T4","T5"], help="Nmap speed (default: T4)")
    parser.add_argument("--top-ports",      type=int, default=1000, help="Nmap top ports (default: 1000)")
    parser.add_argument("--threads",        type=int, default=50,   help="Web crawl threads (default: 50)")
    parser.add_argument("--https",          action="store_true", help="Force HTTPS")
    parser.add_argument("--no-interactive", action="store_true", help="Skip module selector")
    parser.add_argument("--history",        action="store_true", help="Show scan history and exit")
    parser.add_argument("--no-banner",      action="store_true", help="Suppress banner")
    return parser.parse_args()


def main():
    args = get_args()

    if not args.no_banner:
        clear_screen()
        print(BANNER)

    if args.history:
        from modules.scan_history import list_all_history
        list_all_history()
        sys.exit(0)

    if needs_setup():
        setup = input(f"  \033[93m[!] API keys not configured. Run setup? (Y/n): \033[0m").strip().lower()
        if setup in ["", "y", "yes"]:
            first_time_setup()

    if not args.url:
        print(f"\n  \033[96m0xSoamRecon — Red Team Reconnaissance Framework\033[0m")
        print(f"  \033[97mgithub.com/uditsoam/0xSoamRecon\033[0m\n")
        domain = input(f"  \033[93mEnter target domain or IP: \033[0m").strip()
        if not domain:
            log_error("No target provided — exiting")
            sys.exit(1)
    else:
        domain = args.url

    domain = domain.replace("http://","").replace("https://","").rstrip("/")

    json_dir   = os.path.join(args.output, "json")
    report_dir = os.path.join(args.output, "reports")
    screen_dir = os.path.join(args.output, "screenshots")
    os.makedirs(json_dir,   exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(screen_dir, exist_ok=True)
    os.makedirs("history",  exist_ok=True)

    if args.no_interactive:
        selected = sorted([num for num, mod in MODULES.items() if mod["default"]])
        log_info(f"Non-interactive mode — {len(selected)} default modules")
    else:
        selected = interactive_selector(domain)
        if not confirm_scan(selected, domain, args):
            log_warn("Scan cancelled")
            sys.exit(0)

    from modules import (
        subdomain_enum, osint_harvest, shodan_lookup,
        dns_whois, ssl_checker, port_scanner,
        web_crawler, http_headers, screenshot,
        tech_stack, takeover_check, github_dork,
        wayback, email_breach, cve_lookup,
        dork_generator, scan_history
    )
    from aggregator.merge import aggregate
    from reporter.report_generator import generate_report

    start_time = time.time()

    clear_screen()
    print(BANNER)
    print(f"\033[96m{'='*65}\033[0m")
    log_info(f"Target   : \033[92m{domain}\033[0m")
    log_info(f"Modules  : {len(selected)} selected")
    log_info(f"Output   : {args.output}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[96m{'='*65}\033[0m\n")

    if any(m in selected for m in [1,2,3,4,5]):
        log_phase("GROUP 1 — PASSIVE INTELLIGENCE")

    if 1 in selected:
        run_module_safe("Subdomain Enumeration",
            lambda: subdomain_enum.run(domain=domain, output_dir=json_dir))
    if 2 in selected:
        run_module_safe("OSINT Harvesting",
            lambda: osint_harvest.run(domain=domain, output_dir=json_dir))
    if 3 in selected:
        run_module_safe("Shodan Intelligence",
            lambda: shodan_lookup.run(domain=domain, output_dir=json_dir))
    if 4 in selected:
        run_module_safe("DNS & Whois Analysis",
            lambda: dns_whois.run(domain=domain, output_dir=json_dir))
    if 5 in selected:
        run_module_safe("SSL Certificate History",
            lambda: ssl_checker.run(domain=domain, output_dir=json_dir))

    if any(m in selected for m in [6,7,8,9]):
        log_phase("GROUP 2 — ACTIVE RECONNAISSANCE")

    if 6 in selected:
        run_module_safe("Port Scanner",
            lambda: port_scanner.run(
                target=domain, output_dir=json_dir,
                top_ports=args.top_ports, speed=args.speed))
    if 7 in selected:
        run_module_safe("Web Directory Crawler",
            lambda: web_crawler.run(
                domain=domain, output_dir=json_dir,
                threads=args.threads, https=args.https))
    if 8 in selected:
        run_module_safe("HTTP Header Analysis",
            lambda: http_headers.run(
                domain=domain, output_dir=json_dir,
                https=args.https))
    if 9 in selected:
        run_module_safe("Web Screenshots",
            lambda: screenshot.run(
                domain=domain, output_dir=args.output,
                subdomains_json=f"{json_dir}/subdomain_enum.json"))

    if any(m in selected for m in [10,11,12,13]):
        log_phase("GROUP 3 — ADVANCED INTELLIGENCE")

    if 10 in selected:
        run_module_safe("Tech Stack Fingerprint",
            lambda: tech_stack.run(domain=domain, output_dir=json_dir))
    if 11 in selected:
        run_module_safe("Subdomain Takeover Check",
            lambda: takeover_check.run(domain=domain, output_dir=json_dir))
    if 12 in selected:
        run_module_safe("GitHub Dorking",
            lambda: github_dork.run(domain=domain, output_dir=json_dir))
    if 13 in selected:
        run_module_safe("Wayback Machine URLs",
            lambda: wayback.run(domain=domain, output_dir=json_dir))

    if any(m in selected for m in [14,15,16]):
        log_phase("GROUP 4 — OSINT EXTRAS")

    if 14 in selected:
        run_module_safe("Email Breach Check",
            lambda: email_breach.run(domain=domain, output_dir=json_dir))
    if 15 in selected:
        run_module_safe("CVE Auto Lookup",
            lambda: cve_lookup.run(domain=domain, output_dir=json_dir))
    if 16 in selected:
        run_module_safe("Google Dork Generator",
            lambda: dork_generator.run(domain=domain, output_dir=json_dir))

    log_phase("GROUP 5 — REPORT & ANALYSIS")

    log_info("Aggregating all results...")
    merged = aggregate(json_dir=json_dir, domain=domain)

    if 19 in selected:
        log_info("Generating PDF + HTML report...")
        run_module_safe("Report Generation",
            lambda: generate_report(
                json_path  = f"{json_dir}/recon_report.json",
                output_dir = report_dir))

    if 20 in selected:
        elapsed      = round(time.time() - start_time, 1)
        module_names = [MODULES[s]["name"] for s in selected]
        scan_history.save_scan(
            domain      = domain,
            modules_run = module_names,
            summary     = merged.get("summary", {}),
            report_path = report_dir,
            duration    = elapsed)

    elapsed_total = round(time.time() - start_time, 1)
    print_final_summary(merged, domain, elapsed_total, selected)


if __name__ == "__main__":
    main()
