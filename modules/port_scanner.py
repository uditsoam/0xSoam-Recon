#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — Port Scanner Module
#   Author  : Udit Soam
#   Usage   : python3 port_scanner.py -u target.com
#             python3 port_scanner.py -u target.com --top 100
#             python3 port_scanner.py -u target.com --full
#             python3 port_scanner.py -u target.com --speed T3
#             python3 port_scanner.py --help
# ═══════════════════════════════════════════════════════════

import subprocess, json, os, argparse, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = """
\033[91m
 ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
 ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m
\033[97m  [ Module 06 ] Port Scanner — Service & Version Detection\033[0m
\033[93m  Author: Udit Soam | VoidRecon v1.0\033[0m
\033[91m  WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)
def log_info(msg):    print(f"\033[96m  [*] {msg}\033[0m")
def log_success(msg): print(f"\033[92m  [+] {msg}\033[0m")
def log_warn(msg):    print(f"\033[93m  [!] {msg}\033[0m")
def log_error(msg):   print(f"\033[91m  [-] {msg}\033[0m")
def log_port(msg):    print(f"\033[95m      [PORT] {msg}\033[0m")
def log_vuln(msg):    print(f"\033[91m      [VULN] {msg}\033[0m")

def get_args():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="VoidRecon — Port Scanner Module",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py -u target.com
  python3 port_scanner.py -u target.com --top 100
  python3 port_scanner.py -u target.com --full
  python3 port_scanner.py -u target.com --speed T2
  python3 port_scanner.py -u 192.168.1.1 --top 1000
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain or IP address"
    )
    parser.add_argument("--top",
        type=int, default=1000,
        help="Scan top N ports (default: 1000)"
    )
    parser.add_argument("--full",
        action="store_true",
        help="Scan all 65535 ports (slow but thorough)"
    )
    parser.add_argument("--speed",
        default="T4",
        choices=["T1","T2","T3","T4","T5"],
        help="Nmap timing (default: T4)\nT1=stealthy T3=normal T4=fast T5=aggressive"
    )
    parser.add_argument("--udp",
        action="store_true",
        help="Also run UDP scan (requires root)"
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


def classify_port(port):
    high_risk = [21,22,23,25,445,3389,5900,1433,3306,5432,6379,27017]
    med_risk  = [80,443,8080,8443,8888,9090,9200,4443]
    if port in high_risk:
        return "HIGH"
    if port in med_risk:
        return "MEDIUM"
    return "LOW"


def parse_nmap_output(raw_output):
    open_ports = []
    for line in raw_output.split('\n'):
        match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
        if match:
            port_info = {
                "port"    : int(match.group(1)),
                "protocol": match.group(2),
                "service" : match.group(3),
                "version" : match.group(4).strip(),
                "risk"    : classify_port(int(match.group(1)))
            }
            open_ports.append(port_info)
    return open_ports


def run_nmap(target, top_ports, full_scan, speed):
    log_info(f"Running Nmap on: {target}")

    if full_scan:
        port_arg = ["-p-"]
        log_warn("Full port scan — may take 10-15 minutes")
    else:
        port_arg = ["--top-ports", str(top_ports)]

    cmd = ["nmap", "-sV", "-sC", f"-{speed}", "--open", "-oN", "-"] + port_arg + [target]
    log_info(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd, capture_output=True,
            text=True, timeout=600
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log_error("Nmap timed out after 10 minutes")
        return ""
    except FileNotFoundError:
        log_error("Nmap not found — sudo apt install nmap")
        return ""
    except Exception as e:
        log_error(f"Nmap error: {e}")
        return ""


def run(target, output_dir="output/json", top_ports=1000,
        full_scan=False, speed="T4", udp=False):

    os.makedirs(output_dir, exist_ok=True)

    print(f"\n\033[97m{'='*60}\033[0m")
    log_info(f"Target   : {target}")
    log_info(f"Mode     : {'Full (all 65535)' if full_scan else f'Top {top_ports} ports'}")
    log_info(f"Speed    : {speed}")
    log_info(f"Output   : {output_dir}")
    log_info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\033[97m{'='*60}\033[0m\n")

    raw_output = run_nmap(target, top_ports, full_scan, speed)
    open_ports = parse_nmap_output(raw_output)

    if open_ports:
        log_success(f"Found {len(open_ports)} open port(s):")
        for p in open_ports:
            if p['risk'] == 'HIGH':
                color = '\033[91m'
            elif p['risk'] == 'MEDIUM':
                color = '\033[93m'
            else:
                color = '\033[92m'

            log_port(f"{color}{p['port']}/{p['protocol']}\033[0m  "
                     f"{p['service']:<12} {p['version']}  "
                     f"[{color}{p['risk']}\033[0m]")

            if p['port'] == 22:
                log_warn("SSH exposed — check for weak credentials")
            elif p['port'] == 445:
                log_vuln("SMB open — check for EternalBlue")
            elif p['port'] == 3389:
                log_vuln("RDP exposed — check for BlueKeep")
            elif p['port'] == 23:
                log_vuln("Telnet open — unencrypted, critical risk")
            elif p['port'] in [3306, 5432, 1433, 27017, 6379]:
                log_vuln(f"Database port {p['port']} exposed!")
    else:
        log_warn("No open ports found or scan failed")

    high = [p for p in open_ports if p['risk'] == 'HIGH']
    med  = [p for p in open_ports if p['risk'] == 'MEDIUM']
    low  = [p for p in open_ports if p['risk'] == 'LOW']

    data = {
        "module"      : "port_scanner",
        "target"      : target,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_mode"   : "full" if full_scan else f"top_{top_ports}",
        "speed"       : speed,
        "total_open"  : len(open_ports),
        "risk_summary": {
            "high"  : len(high),
            "medium": len(med),
            "low"   : len(low)
        },
        "open_ports"  : open_ports,
        "raw_output"  : raw_output
    }

    out_path = os.path.join(output_dir, "port_scanner.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n\033[97m{'='*60}\033[0m")
    log_success(f"Scan Complete — {len(open_ports)} ports open")
    log_success(f"Risk: HIGH={len(high)} | MEDIUM={len(med)} | LOW={len(low)}")
    log_success(f"Saved -> {out_path}")
    print(f"\033[97m{'='*60}\033[0m\n")
    return data


if __name__ == "__main__":
    args = get_args()
    if not args.no_banner:
        banner()
    run(
        target     = args.url,
        output_dir = args.output,
        top_ports  = args.top,
        full_scan  = args.full,
        speed      = args.speed,
        udp        = args.udp
    )
