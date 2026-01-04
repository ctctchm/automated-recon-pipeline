#!/usr/bin/env python3
"""
Automated Recon Pipeline - Kali Native Version
Author: ctctchm
GitHub: https://github.com/ctctchm/automated-recon-pipeline

Uses only native Kali Linux tools - NO Go dependencies required!

DISCLAIMER: This tool is for educational and authorized security testing only.
Unauthorized access to computer systems is illegal. Always obtain proper 
authorization before conducting security assessments.
"""

import argparse
import subprocess
import json
import os
import sys
import time
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict

class Colors:
    """Terminal color codes"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ReconPipeline:
    def __init__(self, target: str, output_dir: str = None):
        self.target = target
        self.output_dir = output_dir or f"recon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'author': 'ctctchm',
            'subdomains': [],
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'directories': []
        }
        
        # Create output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(f"{self.output_dir}/raw_output").mkdir(exist_ok=True)
        
    def print_banner(self):
        """Display tool banner with author branding"""
        banner = f"""
{Colors.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║      ██████╗████████╗ ██████╗████████╗ ██████╗██╗  ██╗███╗   ███╗
║     ██╔════╝╚══██╔══╝██╔════╝╚══██╔══╝██╔════╝██║  ██║████╗ ████║
║     ██║        ██║   ██║        ██║   ██║     ███████║██╔████╔██║
║     ██║        ██║   ██║        ██║   ██║     ██╔══██║██║╚██╔╝██║
║     ╚██████╗   ██║   ╚██████╗   ██║   ╚██████╗██║  ██║██║ ╚═╝ ██║
║      ╚═════╝   ╚═╝    ╚═════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝
║                                                                ║
║            🔍 AUTOMATED RECONNAISSANCE PIPELINE 🔍             ║
║                                                                ║
║                    Kali Native Edition v2.0                    ║
║                         by ctctchm                             ║
║              github.com/ctctchm/automated-recon-pipeline       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
        
    def print_scan_info(self):
        """Display scan information"""
        print(f"{Colors.BOLD}╔══════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.BOLD}║                    SCAN INFORMATION                      ║{Colors.END}")
        print(f"{Colors.BOLD}╠══════════════════════════════════════════════════════════╣{Colors.END}")
        print(f"{Colors.BOLD}║{Colors.END} {Colors.CYAN}Target:{Colors.END}      {self.target:<46} {Colors.BOLD}║{Colors.END}")
        print(f"{Colors.BOLD}║{Colors.END} {Colors.CYAN}Output Dir:{Colors.END}  {self.output_dir:<46} {Colors.BOLD}║{Colors.END}")
        print(f"{Colors.BOLD}║{Colors.END} {Colors.CYAN}Started:{Colors.END}     {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<46} {Colors.BOLD}║{Colors.END}")
        print(f"{Colors.BOLD}║{Colors.END} {Colors.CYAN}Author:{Colors.END}      ctctchm{' ' * 39} {Colors.BOLD}║{Colors.END}")
        print(f"{Colors.BOLD}╚══════════════════════════════════════════════════════════╝{Colors.END}\n")
    
    def log(self, message: str, level: str = "info"):
        """Formatted logging with enhanced visuals"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        level_config = {
            "info": (Colors.BLUE, "ℹ", "INFO"),
            "success": (Colors.GREEN, "✓", "SUCCESS"),
            "warning": (Colors.YELLOW, "⚠", "WARNING"),
            "error": (Colors.RED, "✗", "ERROR"),
            "scan": (Colors.CYAN, "🔍", "SCAN"),
            "found": (Colors.GREEN, "🎯", "FOUND")
        }
        
        color, symbol, label = level_config.get(level, (Colors.END, '•', 'LOG'))
        
        print(f"{color}[{timestamp}] [{label:^8}] {symbol}  {message}{Colors.END}")
    
    def print_phase_header(self, phase_num: int, phase_name: str, description: str):
        """Print beautiful phase headers"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}║ PHASE {phase_num}: {phase_name.upper():<55} ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}║ {description:<61} ║{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.END}\n")
    
    def run_command(self, command: List[str], output_file: str = None) -> tuple:
        """Execute shell command"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=1200  # 20 minutes
            )
            
            if output_file:
                output_path = f"{self.output_dir}/raw_output/{output_file}"
                with open(output_path, 'w') as f:
                    f.write(result.stdout)
                    if result.stderr:
                        f.write("\n=== STDERR ===\n")
                        f.write(result.stderr)
            
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            self.log("Command timed out", "warning")
            return False, "", "Timeout"
        except Exception as e:
            self.log(f"Error: {e}", "error")
            return False, "", str(e)
    
    def check_dependencies(self) -> bool:
        """Check if tools are installed"""
        self.log("Checking required dependencies...", "scan")
        
        tools = {
            'nmap': 'sudo apt install nmap',
            'host': 'sudo apt install bind9-host',
            'dig': 'sudo apt install dnsutils',
            'nikto': 'sudo apt install nikto',
            'curl': 'sudo apt install curl'
        }
        
        missing = []
        available = []
        
        for tool, install_cmd in tools.items():
            if subprocess.run(['which', tool], capture_output=True).returncode == 0:
                available.append(tool)
                self.log(f"{tool} is available", "success")
            else:
                missing.append((tool, install_cmd))
        
        if missing:
            print(f"\n{Colors.RED}{Colors.BOLD}╔════════════════════════════════════════════╗{Colors.END}")
            print(f"{Colors.RED}{Colors.BOLD}║      MISSING DEPENDENCIES DETECTED!        ║{Colors.END}")
            print(f"{Colors.RED}{Colors.BOLD}╚════════════════════════════════════════════╝{Colors.END}\n")
            for tool, cmd in missing:
                print(f"{Colors.YELLOW}  • {tool:<10}{Colors.END}: {cmd}")
            print(f"\n{Colors.YELLOW}Please install missing tools before running.{Colors.END}\n")
            return False
        
        self.log("All dependencies verified successfully!", "success")
        return True
    
    def subdomain_enumeration(self):
        """Phase 1: Subdomain discovery"""
        self.print_phase_header(1, "Subdomain Enumeration", 
                               "Discovering subdomains using DNS techniques")
        
        subdomains = set([self.target])
        
        # Method 1: DNS brute force
        self.log("Attempting DNS brute force with common subdomains...", "scan")
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 
                       'test', 'portal', 'app', 'mobile', 'vpn', 'blog', 'shop',
                       'cdn', 'secure', 'login', 'dashboard', 'beta', 'demo']
        
        found_count = 0
        for sub in common_subs:
            fqdn = f"{sub}.{self.target}"
            try:
                result = subprocess.run(['host', fqdn], capture_output=True, text=True, timeout=5)
                if 'has address' in result.stdout or 'has IPv6' in result.stdout:
                    subdomains.add(fqdn)
                    found_count += 1
                    self.log(f"Subdomain discovered: {fqdn}", "found")
            except:
                pass
        
        self.log(f"DNS brute force complete: {found_count} subdomains found", "success")
        
        # Method 2: DNS zone transfer
        self.log("Attempting DNS zone transfer (AXFR)...", "scan")
        try:
            ns_result = subprocess.run(['dig', '+short', 'NS', self.target], 
                                     capture_output=True, text=True, timeout=10)
            nameservers = [ns.strip().rstrip('.') for ns in ns_result.stdout.split('\n') if ns.strip()]
            
            if nameservers:
                self.log(f"Found {len(nameservers)} nameservers to test", "info")
                for ns in nameservers[:3]:
                    try:
                        axfr_result = subprocess.run(['dig', f'@{ns}', self.target, 'AXFR'], 
                                                    capture_output=True, text=True, timeout=15)
                        if axfr_result.returncode == 0 and 'Transfer failed' not in axfr_result.stdout:
                            for line in axfr_result.stdout.split('\n'):
                                if self.target in line and '\tA\t' in line:
                                    parts = line.split()
                                    if parts:
                                        subdomain = parts[0].rstrip('.')
                                        if subdomain.endswith(self.target):
                                            if subdomain not in subdomains:
                                                subdomains.add(subdomain)
                                                self.log(f"Zone transfer found: {subdomain}", "found")
                    except:
                        pass
            else:
                self.log("No nameservers found for zone transfer", "warning")
        except:
            self.log("Zone transfer attempt failed", "warning")
        
        # Method 3: Certificate transparency
        self.log("Querying certificate transparency logs...", "scan")
        try:
            ct_result = subprocess.run(
                ['curl', '-s', f'https://crt.sh/?q=%.{self.target}&output=json'],
                capture_output=True, text=True, timeout=30
            )
            if ct_result.returncode == 0:
                try:
                    ct_data = json.loads(ct_result.stdout)
                    ct_count = 0
                    for entry in ct_data[:50]:
                        name = entry.get('name_value', '').strip()
                        if name and not name.startswith('*') and name not in subdomains:
                            subdomains.add(name)
                            ct_count += 1
                    self.log(f"Certificate transparency: {ct_count} new subdomains", "success")
                except:
                    self.log("Failed to parse certificate data", "warning")
        except:
            self.log("Certificate transparency check skipped", "warning")
        
        self.results['subdomains'] = sorted(list(subdomains))
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Phase 1 Complete!                   ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Total Subdomains: {len(subdomains):<18} ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.END}\n")
        
        with open(f"{self.output_dir}/subdomains.txt", 'w') as f:
            f.write('\n'.join(self.results['subdomains']))
    
    def port_scanning(self):
        """Phase 2: Port scanning"""
        self.print_phase_header(2, "Port Scanning", 
                               "Scanning for open ports and services")
        
        targets = self.results['subdomains'][:5]
        self.log(f"Scanning {len(targets)} targets with Nmap...", "scan")
        
        all_ports = []
        
        for idx, target in enumerate(targets, 1):
            self.log(f"[{idx}/{len(targets)}] Scanning {target}...", "scan")
            
            success, stdout, _ = self.run_command(
                ['nmap', '-T4', '-F', '--open', target],
                f'nmap_{target.replace(".", "_")}.txt'
            )
            
            if success:
                port_count = 0
                for line in stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2]
                            port = port_proto.split('/')[0]
                            
                            all_ports.append({
                                'host': target,
                                'port': port,
                                'protocol': 'tcp',
                                'service': service,
                                'state': state
                            })
                            port_count += 1
                            self.log(f"  {target}:{port} → {service}", "found")
                
                if port_count == 0:
                    self.log(f"  No open ports found on {target}", "info")
        
        self.results['ports'] = all_ports
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Phase 2 Complete!                   ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Total Open Ports: {len(all_ports):<18} ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.END}\n")
    
    def service_enumeration(self):
        """Phase 3: Service detection"""
        self.print_phase_header(3, "Service Enumeration", 
                               "Detecting live web services")
        
        services = []
        targets = self.results['subdomains'][:10]
        
        self.log(f"Probing {len(targets)} targets for HTTP/HTTPS services...", "scan")
        
        for subdomain in targets:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain}"
                try:
                    result = subprocess.run(
                        ['curl', '-I', '-s', '-m', '5', url],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout:
                        lines = result.stdout.split('\n')
                        status = lines[0] if lines else ''
                        server = ''
                        
                        for line in lines:
                            if line.lower().startswith('server:'):
                                server = line.split(':', 1)[1].strip()
                                break
                        
                        if '200' in status or '301' in status or '302' in status or '403' in status:
                            services.append({
                                'url': url,
                                'status': status.split()[1] if len(status.split()) > 1 else 'Unknown',
                                'server': server or 'Unknown'
                            })
                            self.log(f"Live service: {url} [{status.split()[1] if status.split() else 'Unknown'}]", "found")
                except:
                    pass
        
        self.results['services'] = services
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Phase 3 Complete!                   ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Live Web Services: {len(services):<18} ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.END}\n")
    
    def vulnerability_scanning(self):
        """Phase 4: Vulnerability scanning"""
        self.print_phase_header(4, "Vulnerability Scanning", 
                               "Scanning for security vulnerabilities")
        
        vulnerabilities = []
        web_services = [s for s in self.results['services'] if 'http' in s.get('url', '')][:3]
        
        if not web_services:
            self.log("No web services to scan", "warning")
            print(f"\n{Colors.YELLOW}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.END}")
            print(f"{Colors.YELLOW}{Colors.BOLD}║  Phase 4 Skipped - No web services  ║{Colors.END}")
            print(f"{Colors.YELLOW}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.END}\n")
            return
        
        self.log(f"Running Nikto on {len(web_services)} web service(s)...", "scan")
        
        for idx, service in enumerate(web_services, 1):
            url = service['url']
            self.log(f"[{idx}/{len(web_services)}] Scanning {url}...", "scan")
            
            success, stdout, _ = self.run_command(
                ['nikto', '-h', url, '-Tuning', '123456789', '-maxtime', '300'],
                f'nikto_{url.replace("://", "_").replace("/", "_")}.txt'
            )
            
            if success and stdout:
                vuln_count = 0
                for line in stdout.split('\n'):
                    if '+ ' in line and ('OSVDB' in line or 'vulnerab' in line.lower()):
                        vulnerabilities.append({
                            'target': url,
                            'finding': line.strip()
                        })
                        vuln_count += 1
                
                if vuln_count > 0:
                    self.log(f"  {vuln_count} potential issue(s) found on {url}", "warning")
        
        self.results['vulnerabilities'] = vulnerabilities
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Phase 4 Complete!                   ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Security Findings: {len(vulnerabilities):<18} ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════╝{Colors.END}\n")
    
    def generate_html_report(self):
        """Generate HTML report"""
        self.log("Generating HTML report...", "scan")
        
        # Prepare HTML fragments
        subdomains_html = ''.join([f'<div class="item"><code>{s}</code></div>' 
                                   for s in self.results['subdomains'][:30]])
        if len(self.results['subdomains']) > 30:
            subdomains_html += f'<p class="more">...and {len(self.results["subdomains"]) - 30} more</p>'
        
        ports_html = ''.join([
            f'<div class="item"><strong>{p["host"]}</strong> : '
            f'<span class="port">{p["port"]}/{p["protocol"]} - {p["service"]}</span></div>'
            for p in self.results['ports'][:30]
        ])
        if len(self.results['ports']) > 30:
            ports_html += f'<p class="more">...and {len(self.results["ports"]) - 30} more</p>'
        
        services_html = ''.join([
            f'<div class="item"><strong>{s["url"]}</strong> - Status: {s["status"]} - Server: {s["server"]}</div>'
            for s in self.results['services'][:20]
        ])
        if len(self.results['services']) > 20:
            services_html += f'<p class="more">...and {len(self.results["services"]) - 20} more</p>'
        
        vulns_html = ''.join([
            f'<div class="item vulnerability">{v["finding"]}</div>'
            for v in self.results['vulnerabilities'][:30]
        ]) if self.results['vulnerabilities'] else '<div class="item">No vulnerabilities detected</div>'
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {self.target} by ctctchm</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.1em; opacity: 0.9; }}
        .author-badge {{ display: inline-block; background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; margin-top: 15px; font-weight: bold; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card .number {{ font-size: 2.5em; font-weight: bold; color: #667eea; }}
        .stat-card .label {{ color: #666; margin-top: 10px; }}
        .section {{ padding: 30px; }}
        .section h2 {{ color: #667eea; margin-bottom: 20px; font-size: 1.8em; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .item {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #667eea; }}
        .item code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        .vulnerability {{ border-left-color: #dc3545; background: #fff5f5; }}
        .port {{ display: inline-block; background: #667eea; color: white; padding: 5px 10px; border-radius: 5px; margin: 5px; font-size: 0.9em; }}
        .footer {{ text-align: center; padding: 20px; background: #f8f9fa; color: #666; }}
        .footer a {{ color: #667eea; text-decoration: none; font-weight: bold; }}
        .footer a:hover {{ text-decoration: underline; }}
        .timestamp {{ color: #999; font-size: 0.9em; }}
        .more {{ color: #666; margin-top: 10px; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Reconnaissance Report</h1>
            <p>Target: <strong>{self.target}</strong></p>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="author-badge">👨‍💻 Created by ctctchm</div>
            <p style="margin-top: 10px; font-size: 0.9em;">Kali Native Tools - No Go Required</p>
        </div>
        
        <div class="stats">
            <div class="stat-card"><div class="number">{len(self.results['subdomains'])}</div><div class="label">Subdomains</div></div>
            <div class="stat-card"><div class="number">{len(self.results['ports'])}</div><div class="label">Open Ports</div></div>
            <div class="stat-card"><div class="number">{len(self.results['services'])}</div><div class="label">Web Services</div></div>
            <div class="stat-card"><div class="number">{len(self.results['vulnerabilities'])}</div><div class="label">Findings</div></div>
        </div>
        
        <div class="section">
            <h2>📋 Subdomains Discovered</h2>
            {subdomains_html if subdomains_html else '<div class="item">No subdomains found</div>'}
        </div>
        
        <div class="section">
            <h2>🔌 Open Ports</h2>
            {ports_html if ports_html else '<div class="item">No open ports detected</div>'}
        </div>
        
        <div class="section">
            <h2>🌐 Live Web Services</h2>
            {services_html if services_html else '<div class="item">No web services detected</div>'}
        </div>
        
        <div class="section">
            <h2>⚠️ Security Findings</h2>
            {vulns_html}
        </div>
        
        <div class="footer">
            <p><strong>Automated Recon Pipeline v2.0</strong> - Kali Native Edition</p>
            <p>Created by <a href="https://github.com/ctctchm" target="_blank">ctctchm</a></p>
            <p style="margin-top: 10px;">
                <a href="https://github.com/ctctchm/automated-recon-pipeline" target="_blank">
                    ⭐ Star on GitHub
                </a>
            </p>
            <p style="margin-top: 15px; color: #dc3545;">⚠️ For authorized security testing only</p>
        </div>
    </div>
</body>
</html>"""
        
        report_path = f"{self.output_dir}/report.html"
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        self.log(f"HTML report saved: {report_path}", "success")
        
        # Save JSON
        json_path = f"{self.output_dir}/results.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log(f"JSON data saved: {json_path}", "success")
    
    def print_summary(self, elapsed_time: float):
        """Print final summary"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'═' * 70}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}║{'SCAN COMPLETE - SUMMARY':^68}║{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 70}{Colors.END}\n")
        
        print(f"{Colors.GREEN}✓ Subdomains discovered:{Colors.END} {len(self.results['subdomains'])}")
        print(f"{Colors.GREEN}✓ Open ports found:{Colors.END} {len(self.results['ports'])}")
        print(f"{Colors.GREEN}✓ Live web services:{Colors.END} {len(self.results['services'])}")
        print(f"{Colors.GREEN}✓ Security findings:{Colors.END} {len(self.results['vulnerabilities'])}")
        print(f"{Colors.GREEN}✓ Time elapsed:{Colors.END} {elapsed_time:.2f} seconds")
        print(f"{Colors.GREEN}✓ Output directory:{Colors.END} {self.output_dir}")
        
        print(f"\n{Colors.BOLD}📊 View your results:{Colors.END}")
        print(f"  HTML Report: {Colors.CYAN}{self.output_dir}/report.html{Colors.END}")
        print(f"  JSON Data:   {Colors.CYAN}{self.output_dir}/results.json{Colors.END}")
        
        print(f"\n{Colors.BOLD}Created by: {Colors.CYAN}ctctchm{Colors.END}")
        print(f"{Colors.BOLD}GitHub: {Colors.CYAN}https://github.com/ctctchm/automated-recon-pipeline{Colors.END}\n")
        
        print(f"{Colors.CYAN}{Colors.BOLD}{'═' * 70}{Colors.END}\n")
    
    def run(self):
        """Execute pipeline"""
        self.print_banner()
        self.print_scan_info()
        
        if not self.check_dependencies():
            return
        
        print(f"\n{Colors.YELLOW}⚠️  Starting reconnaissance - This may take several minutes...{Colors.END}\n")
        
        start_time = time.time()
        
        try:
            self.subdomain_enumeration()
            self.port_scanning()
            self.service_enumeration()
            self.vulnerability_scanning()
            self.generate_html_report()
            
            elapsed = time.time() - start_time
            self.print_summary(elapsed)
            
        except KeyboardInterrupt:
            print(f"\n\n{Colors.RED}╔════════════════════════════════════╗{Colors.END}")
            print(f"{Colors.RED}║  Scan interrupted by user!         ║{Colors.END}")
            print(f"{Colors.RED}╚════════════════════════════════════╝{Colors.END}\n")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.RED}Error during scan: {e}{Colors.END}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.CYAN}Automated Recon Pipeline - Kali Native Edition{Colors.END}\nby ctctchm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BOLD}Examples:{Colors.END}
  python3 recon_pipeline.py -t example.com
  python3 recon_pipeline.py -t example.com -o my_scan_results

{Colors.BOLD}Tools used:{Colors.END}
  • Nmap      - Port scanning
  • Host/Dig  - DNS enumeration  
  • Curl      - Service detection
  • Nikto     - Vulnerability scanning

{Colors.BOLD}Author:{Colors.END} ctctchm
{Colors.BOLD}GitHub:{Colors.END} https://github.com/ctctchm/automated-recon-pipeline

{Colors.RED}Disclaimer: For authorized testing only.{Colors.END}
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target domain (e.g., example.com)')
    parser.add_argument('-o', '--output', 
                       help='Custom output directory name')
    
    args = parser.parse_args()
    
    pipeline = ReconPipeline(args.target, args.output)
    pipeline.run()

if __name__ == "__main__":
    main()
