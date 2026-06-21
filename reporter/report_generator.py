#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Report Generator
#   Author  : Udit Soam
#   Usage   : python3 report_generator.py -j output/json/recon_report.json
#             python3 report_generator.py -j output/json/recon_report.json --pdf-only
#             python3 report_generator.py --help
# ═══════════════════════════════════════════════════════════

import json, os, argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from colorama import Fore, Style, init
init(autoreset=True)

def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")

def get_args():
    parser = argparse.ArgumentParser(
        prog="report_generator.py",
        description="0xSoamRecon — PDF & HTML Report Generator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 reporter/report_generator.py -j output/json/recon_report.json
  python3 reporter/report_generator.py -j output/json/recon_report.json --pdf-only
  python3 reporter/report_generator.py -j output/json/recon_report.json --html-only
  python3 reporter/report_generator.py -j output/json/recon_report.json -o /tmp/reports
        """
    )
    parser.add_argument("-j", "--json",
        required=True,
        help="Path to recon_report.json from aggregator"
    )
    parser.add_argument("-o", "--output",
        default="output/reports",
        help="Output directory for reports (default: output/reports)"
    )
    parser.add_argument("--pdf-only",
        action="store_true",
        help="Generate PDF only"
    )
    parser.add_argument("--html-only",
        action="store_true",
        help="Generate HTML only"
    )
    return parser.parse_args()


def load_report_data(json_path):
    log_info(f"Loading report data from: {json_path}")
    try:
        with open(json_path, "r") as f:
            return json.load(f)
    except Exception as e:
        log_error(f"Cannot read JSON: {e}")
        return None


def render_html(data, template_dir):
    log_info("Rendering HTML template...")
    try:
        env      = Environment(
            loader=FileSystemLoader(template_dir)
        )
        template = env.get_template("report.html")

        html = template.render(
            domain          = data["meta"]["domain"],
            author          = data["meta"]["author"],
            scan_date       = data["meta"]["timestamp"],
            summary         = data["summary"],
            subdomains      = data.get("subdomains", []),
            emails          = data.get("emails", []),
            open_ports      = data.get("open_ports", []),
            web_paths       = data.get("web_paths", []),
            http_headers    = data.get("http_headers", {}),
            dns_records     = data.get("dns_records", {}),
            whois           = data.get("whois", {}),
            ssl_certs       = data.get("ssl_certs", []),
            shodan          = data.get("shodan", []),
            screenshots     = data.get("screenshots", []),
            tech_stack      = data.get("tech_stack", {}),
            github_findings = data.get("github_findings", []),
            risk_analysis   = data.get("risk_analysis", {}),
            dorks           = data.get("dorks", []),
        )
        log_success("HTML rendered successfully")
        return html
    except Exception as e:
        log_error(f"HTML render error: {e}")
        return None


def save_html(html_content, output_dir, domain):
    os.makedirs(output_dir, exist_ok=True)
    safe_domain = domain.replace(".", "_").replace("/", "_")
    filename    = f"0xSoamRecon_{safe_domain}.html"
    filepath    = os.path.join(output_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        log_success(f"HTML saved → {filepath}")
        return filepath
    except Exception as e:
        log_error(f"HTML save error: {e}")
        return None


def save_pdf(html_content, output_dir, domain):
    os.makedirs(output_dir, exist_ok=True)
    safe_domain = domain.replace(".", "_").replace("/", "_")
    filename    = f"0xSoamRecon_{safe_domain}.pdf"
    filepath    = os.path.join(output_dir, filename)
    log_info(f"Generating PDF (this may take 15-30 seconds)...")
    try:
        from weasyprint import HTML, CSS
        HTML(string=html_content).write_pdf(filepath)
        size_kb = os.path.getsize(filepath) // 1024
        log_success(f"PDF saved → {filepath} ({size_kb} KB)")
        return filepath
    except Exception as e:
        log_error(f"PDF generation error: {e}")
        log_warn("Try: pip install weasyprint --break-system-packages")
        return None


def generate_report(json_path, output_dir="output/reports",
                    pdf_only=False, html_only=False):

    template_dir = os.path.join(
        os.path.dirname(__file__), "templates"
    )

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_info(f"JSON input   : {json_path}")
    log_info(f"Output dir   : {output_dir}")
    log_info(f"Template dir : {template_dir}")
    log_info(f"Mode         : {'PDF only' if pdf_only else 'HTML only' if html_only else 'PDF + HTML'}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    # Load data
    data = load_report_data(json_path)
    if not data:
        return None, None

    domain = data.get("meta", {}).get("domain", "unknown")

    # Render HTML
    html_content = render_html(data, template_dir)
    if not html_content:
        return None, None

    html_path = None
    pdf_path  = None

    # Save HTML
    if not pdf_only:
        html_path = save_html(html_content, output_dir, domain)

    # Save PDF
    if not html_only:
        pdf_path = save_pdf(html_content, output_dir, domain)

    print(f"\n{Fore.WHITE}{'═'*55}{Style.RESET_ALL}")
    log_success("Report generation complete!")
    if html_path: log_success(f"HTML → {html_path}")
    if pdf_path:  log_success(f"PDF  → {pdf_path}")
    print(f"{Fore.WHITE}{'═'*55}{Style.RESET_ALL}\n")

    return html_path, pdf_path


if __name__ == "__main__":
    args = get_args()
    generate_report(
        json_path  = args.json,
        output_dir = args.output,
        pdf_only   = args.pdf_only,
        html_only  = args.html_only
    )
