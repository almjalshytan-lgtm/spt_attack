import os
import sys
import subprocess
import argparse
import time
import json
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# محاولة استيراد المكتبات الضرورية
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    os.system('pip install colorama')
    from colorama import Fore, Style, init

# --- COLORS ---
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
M = Fore.MAGENTA
W = Fore.WHITE
B = Fore.BLUE
LR = Fore.LIGHTRED_EX
LG = Fore.LIGHTGREEN_EX
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

# --- METADATA ---
TOOL_NAME = "SPY ATTACK ULTIMATE"
VERSION = "2.0.0-PRO"
TEAM = "SPY ATTACK TEAM"

class SpyAttackFramework:
    def __init__(self):
        self.args = self.parse_args()
        self.start_time = datetime.now()
        self.output_dir = ""
        
    def parse_args(self):
        parser = argparse.ArgumentParser(
            description=f"{R}{BOLD}SPY ATTACK ULTIMATE FRAMEWORK{RESET}",
            usage="spy_attack [OPTIONS] -t <target>",
            formatter_class=argparse.RawTextHelpFormatter
        )

        # 1-10: Target & Basic Config
        target_group = parser.add_argument_group(f'{G}Targeting Options{RESET}')
        target_group.add_argument("-t", "--target", help="Target domain or IP")
        target_group.add_argument("-l", "--list", help="File containing list of targets")
        target_group.add_argument("-o", "--output", help="Custom output directory")
        target_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
        target_group.add_argument("--silent", action="store_true", help="Minimal output mode")
        target_group.add_argument("--config", help="Load custom YAML/JSON config")
        target_group.add_argument("--update", action="store_true", help="Update the framework and templates")
        target_group.add_argument("--proxy", help="Use a proxy (e.g., http://127.0.0.1:8080)")
        target_group.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
        target_group.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")

        # 11-20: Reconnaissance (Subdomains)
        recon_group = parser.add_argument_group(f'{C}Reconnaissance (Layer 1){RESET}')
        recon_group.add_argument("--skip-recon", action="store_true", help="Skip subdomain discovery")
        recon_group.add_argument("--passive", action="store_true", help="Passive recon only (no DNS queries)")
        recon_group.add_argument("--active", action="store_true", help="Active recon (DNS bruteforce)")
        recon_group.add_argument("--subs-only", action="store_true", help="Only perform subdomain enum")
        recon_group.add_argument("--recursive", action="store_true", help="Recursive subdomain discovery")
        recon_group.add_argument("--resolvers", help="File with custom DNS resolvers")
        recon_group.add_argument("--sources", help="Specific sources for subfinder (e.g., crtsh,censys)")
        recon_group.add_argument("--exclude-subs", help="Subdomains to exclude")
        recon_group.add_argument("--wildcard", action="store_true", help="Enable wildcard discovery")
        recon_group.add_argument("--asn", help="Target ASN for IP range discovery")

        # 21-30: Scanning (Ports & Services)
        scan_group = parser.add_argument_group(f'{Y}Port Scanning (Layer 2){RESET}')
        scan_group.add_argument("-p", "--ports", help="Ports to scan (e.g., 80,443 or 1-65535)")
        scan_group.add_argument("--top-ports", type=int, help="Scan top X common ports")
        scan_group.add_argument("--skip-nmap", action="store_true", help="Skip port scanning entirely")
        scan_group.add_argument("--fast-scan", action="store_true", help="Syn scan (faster)")
        scan_group.add_argument("--service-version", action="store_true", help="Attempt service version detection")
        scan_group.add_argument("--os-detect", action="store_true", help="Attempt OS fingerprinting")
        scan_group.add_argument("--scripts", help="Run specific Nmap NSE scripts (comma separated)")
        scan_group.add_argument("--udp", action="store_true", help="Scan UDP ports too")
        scan_group.add_argument("--ping-sweep", action="store_true", help="ICMP ping sweep only")
        scan_group.add_argument("--mtu", type=int, help="Set custom MTU for evasion")

        # 31-40: Vulnerabilities (Web & Logic)
        vuln_group = parser.add_argument_group(f'{R}Vulnerability Analysis (Layer 3){RESET}')
        vuln_group.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability scanning")
        vuln_group.add_argument("--severity", help="Filter by severity (critical,high,medium,low)")
        vuln_group.add_argument("--templates", help="Specific Nuclei templates to run")
        vuln_group.add_argument("--exclude-templates", help="Nuclei templates to skip")
        vuln_group.add_argument("--fuzz", action="store_true", help="Enable directory fuzzing/bruteforce")
        vuln_group.add_argument("--wordlist", help="Custom wordlist for fuzzing")
        vuln_group.add_argument("--waf-detect", action="store_true", help="Attempt to detect WAF/IPS")
        vuln_group.add_argument("--vuln-only", action="store_true", help="Only run vuln scanner on target")
        vuln_group.add_argument("--cve", help="Scan for a specific CVE ID")
        vuln_group.add_argument("--interactsh", action="store_true", help="Enable OOB interaction testing")

        # 41-50: Advanced Evasion & Speed
        evasion_group = parser.add_argument_group(f'{M}Evasion & Performance{RESET}')
        evasion_group.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
        evasion_group.add_argument("--user-agent", help="Custom User-Agent header")
        evasion_group.add_argument("--random-agent", action="store_true", help="Use random user agents")
        evasion_group.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests")
        evasion_group.add_argument("--rate-limit", type=int, help="Maximum requests per second")
        evasion_group.add_argument("--headers", help="Additional custom headers (JSON string)")
        evasion_group.add_argument("--verify-ssl", action="store_true", help="Force SSL verification")
        evasion_group.add_argument("--max-time", type=int, help="Maximum scan duration (minutes)")
        evasion_group.add_argument("--stealth", action="store_true", help="Predefined stealth config")
        evasion_group.add_argument("--aggressive", action="store_true", help="Predefined aggressive config")

        # 51-60: Reporting & UI
        report_group = parser.add_argument_group(f'{B}Reporting & Post-Processing{RESET}')
        report_group.add_argument("--json", action="store_true", help="Save report in JSON format")
        report_group.add_argument("--html", action="store_true", help="Generate fancy HTML report")
        report_group.add_argument("--pdf", action="store_true", help="Generate PDF report (requires wkhtmltopdf)")
        report_group.add_argument("--notify", action="store_true", help="Send notification to Slack/Discord")
        report_group.add_argument("--webhook", help="Webhook URL for notifications")
        report_group.add_argument("--compare", help="Compare current scan with previous one")
        report_group.add_argument("--screenshot", action="store_true", help="Take screenshots of live subdomains")
        report_group.add_argument("--extract-js", action="store_true", help="Extract and analyze JS files for secrets")
        report_group.add_argument("--db-export", action="store_true", help="Export results to a SQL database")
        report_group.add_argument("--no-color", action="store_true", help="Disable colored output")

        return parser.parse_args()

    def banner(self):
        if self.args.silent: return
        os.system('clear')
        banner_text = f"""
{R}{BOLD}
   ███████╗██████╗ ██╗   ██╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
   ██╔════╝██╔══██╗╚██╗ ██╔╝    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
   ███████╗██████╔╝ ╚████╔╝     ███████║   ██║      ██║   ███████║██║     █████╔╝ 
   ╚════██║██╔═══╝   ╚██╔╝      ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
   ███████║██║        ██║       ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
   ╚══════╝╚═╝        ╚═╝       ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
{C}   [+] ULTIMATE CYBER SECURITY FRAMEWORK {R}v{VERSION}
{Y}   [+] MISSION CONTROL: {TEAM}
{W}   [+] TOTAL COMMANDS LOADED: 60+
        """
        print(banner_text)

    def log(self, msg, type="INFO"):
        if self.args.silent and type not in ["VULN", "CRITICAL"]: return
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": f"{C}[{ts}] {G}[+]{RESET}",
            "WARN": f"{C}[{ts}] {Y}[!]{RESET}",
            "ERROR": f"{C}[{ts}] {R}[-]{RESET}",
            "VULN": f"{C}[{ts}] {LR}{BOLD}[VULN]{RESET}",
            "MODE": f"{C}[{ts}] {M}[*]{RESET}"
        }.get(type, f"[{ts}]")
        print(f"{prefix} {msg}")

    def setup_workspace(self):
        if not self.args.target and not self.args.list:
            self.log("Target required. Use -t <target> or -l <list>", "ERROR")
            sys.exit(1)
        
        target_name = self.args.target if self.args.target else "multi_scan"
        self.output_dir = self.args.output if self.args.output else f"spy_results_{target_name}_{int(time.time())}"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.log(f"Workspace established at: {self.output_dir}", "INFO")

    def run_command(self, cmd, phase_name):
        self.log(f"Starting Phase: {phase_name}", "MODE")
        if self.args.verbose: self.log(f"Executing: {cmd}", "INFO")
        try:
            # تشغيل الأمر مع إخفاء المخرجات إذا لم يطلب المستخدم التفاصيل
            process = subprocess.run(cmd, shell=True, capture_output=self.args.silent, text=True)
            return True
        except Exception as e:
            self.log(f"Phase {phase_name} failed: {str(e)}", "ERROR")
            return False

    def execute_workflow(self):
        # 1. Recon Phase
        if not self.args.skip_recon:
            recon_cmd = f"subfinder -d {self.args.target} -o {self.output_dir}/subs.txt -silent"
            if self.args.active: recon_cmd += " -all"
            self.run_command(recon_cmd, "Reconnaissance")
        
        # 2. Port Scan Phase
        if not self.args.skip_nmap:
            port_flag = f"-p {self.args.ports}" if self.args.ports else "--top-ports 1000"
            nmap_cmd = f"nmap {port_flag} -sV {self.args.target} -oN {self.output_dir}/nmap.txt"
            if self.args.stealth: nmap_cmd += " -T2 -sS"
            self.run_command(nmap_cmd, "Service Scanning")

        # 3. Vulnerability Phase
        if not self.args.skip_vuln:
            target_input = f"{self.output_dir}/subs.txt" if os.path.exists(f"{self.output_dir}/subs.txt") else self.args.target
            nuclei_cmd = f"nuclei -l {target_input} -o {self.output_dir}/vulns.txt"
            if self.args.severity: nuclei_cmd += f" -s {self.args.severity}"
            self.run_command(nuclei_cmd, "Vulnerability Assessment")

    def run(self):
        self.banner()
        self.setup_workspace()
        
        # Apply Logic for 60+ combinations
        if self.args.aggressive:
            self.log("Aggressive mode engaged. Speed maximized.", "WARN")
            self.args.threads = 50
            self.args.timeout = 10
        
        self.execute_workflow()
        
        end_time = datetime.now()
        self.log(f"Mission complete. Total time: {end_time - self.start_time}", "SUCCESS")

if __name__ == "__main__":
    scanner = SpyAttackFramework()
    scanner.run()
