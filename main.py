#!/usr/bin/env python3
# REloadAI v2.0 - Automated Binary Analysis & Exploit Generation
# Author: REload
# Date: 04/2025

import os
import sys
import argparse
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.live import Live
from rich.markdown import Markdown

from core.analyzer import BinaryAnalyzer
from core.exploit_gen import ExploitGenerator
from monetization.licensing import LicenseManager
from monetization.analytics import UsageAnalytics
from api.rest_api import app

import uvicorn

# Setup console and logging
console = Console()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("REloadAI")

class REloadAI:
    def __init__(self):
        self.console = console
        self.license_manager = None
        self.exploit_generator = None
        self.analytics = None
    
    def setup(self, license_key: str = None):
        """Initialize components"""
        self.console.print("[bold green]REloadAI Initializing...[/bold green]")
        
        # Load API keys
        if license_key:
            self.license_manager = LicenseManager(os.getenv("LICENSE_SECRET_KEY"))
            license_info = self.license_manager.validate_license(license_key)
            self.console.print(f"[green]License validated for: {license_info['user_email']}[/green]")
        
        openai_key = os.getenv("OPENAI_API_KEY") or self._load_api_key()
        self.exploit_generator = ExploitGenerator(openai_key)
        self.console.print("[green]Exploit generator initialized[/green]")
    
    def _load_api_key(self):
        """Load OpenAI API key from file"""
        api_key_path = os.path.expanduser("~/.r2ai.openai-key")
        if os.path.exists(api_key_path):
            with open(api_key_path, 'r') as f:
                return f.read().strip()
        else:
            self.console.print("[red]OpenAI API key not found. Please set OPENAI_API_KEY environment variable or create ~/.r2ai.openai-key file[/red]")
            sys.exit(1)
    
    def analyze_file(self, file_path: str, features: List[str] = None):
        """Analyze a binary file"""
        if not features:
            features = ["basic_analysis", "string_extraction", "function_analysis"]
        
        self.console.rule(f"[bold blue]Analyzing {os.path.basename(file_path)}[/bold blue]")
        
        analyzer = BinaryAnalyzer(file_path)
        analyzer.connect()
        
        results = {}
        
        # Basic info
        if "basic_analysis" in features:
            with self.console.status("[bold green]Getting file info..."):
                results['file_info'] = analyzer.get_file_info()
                results['protections'] = analyzer.analyze_protections()
            
            self._display_file_info(results['file_info'])
            self._display_protections(results['protections'])
        
        # Strings
        if "string_extraction" in features:
            with self.console.status("[bold green]Extracting strings..."):
                results['strings'] = analyzer.extract_strings()
            
            self._display_strings(results['strings'])
        
        # Functions and vulnerabilities
        if "function_analysis" in features:
            with self.console.status("[bold green]Analyzing functions..."):
                results['functions'] = analyzer.analyze_functions()
                
                # Collect vulnerabilities
                vulnerabilities = []
                for func in results['functions']:
                    if func.get('vulnerabilities'):
                        vulnerabilities.extend(func['vulnerabilities'])
                results['vulnerabilities'] = vulnerabilities
            
            self._display_functions(results['functions'])
            self._display_vulnerabilities(vulnerabilities)
            
            # Generate exploits if vulnerabilities found
            if vulnerabilities and self.exploit_generator:
                self._generate_exploits(analyzer, vulnerabilities)
        
        analyzer.close()
        return results
    
    def _display_file_info(self, info: Dict):
        """Display file information"""
        table = Table(title="File Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in info.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def _display_protections(self, protections: Dict):
        """Display security protections"""
        table = Table(title="Security Protections")
        table.add_column("Protection", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Description", style="white")
        
        descriptions = {
            'canary': "Stack canary to detect buffer overflows",
            'nx': "No-Execute bit to prevent code execution on stack",
            'pic': "Position Independent Code for ASLR",
            'relro': "RELRO (Relocation Read-Only) to protect GOT",
            'fortify': "Fortified source functions for buffer overflow prevention"
        }
        
        for key, value in protections.items():
            status = "Enabled" if value else "Disabled"
            if key == 'relro' and value not in [True, False]:
                status = value  # Full, Partial, None
            
            table.add_row(key.upper(), status, descriptions.get(key, ""))
        
        self.console.print(table)
    
    def _display_strings(self, strings: List[Dict]):
        """Display interesting strings"""
        interesting = [s for s in strings if s.get('interesting')]
        
        if interesting:
            self.console.print("\n[bold yellow]Interesting Strings:[/bold yellow]")
            for s in interesting[:10]:  # Limit to 10
                self.console.print(f"• {s['string']}", style="yellow")
            
            if len(interesting) > 10:
                self.console.print(f"... and {len(interesting) - 10} more")
    
    def _display_functions(self, functions: List[Dict]):
        """Display function information"""
        vuln_functions = [f for f in functions if f.get('vulnerabilities')]
        
        if vuln_functions:
            self.console.print("\n[bold red]Functions with Vulnerabilities:[/bold red]")
            table = Table()
            table.add_column("Function", style="red")
            table.add_column("Address", style="cyan")
            table.add_column("Vulnerabilities", style="yellow")
            
            for func in vuln_functions:
                vuln_types = [v['type'] for v in func['vulnerabilities']]
                table.add_row(func['name'], hex(func['offset']), ", ".join(vuln_types))
            
            self.console.print(table)
    
    def _display_vulnerabilities(self, vulnerabilities: List[Dict]):
        """Display vulnerabilities found"""
        if vulnerabilities:
            self.console.print("\n[bold red]Vulnerabilities Found:[/bold red]")
            for i, vuln in enumerate(vulnerabilities, 1):
                self.console.print(Panel(
                    f"[bold]{vuln['type']}[/bold]\n"
                    f"Function: {vuln.get('function', 'unknown')}\n"
                    f"Reason: {vuln.get('reason', 'No details')}",
                    title=f"Vulnerability #{i}",
                    border_style="red"
                ))
    
    def _generate_exploits(self, analyzer: BinaryAnalyzer, vulnerabilities: List[Dict]):
        """Generate exploits for vulnerabilities"""
        self.console.print("\n[bold yellow]Generating Exploits...[/bold yellow]")
        
        main_func = analyzer.get_main_function()
        if main_func:
            main_disasm = analyzer.get_disassembly(main_func['offset'])
            
            for vuln in vulnerabilities:
                self.console.rule(f"[bold magenta]Exploit for {vuln['type']}[/bold magenta]")
                
                # Generate exploit
                exploit_code = self.exploit_generator.generate_exploit(vuln, main_disasm, 'python')
                self.console.print(Panel(
                    Markdown(f"```python\n{exploit_code}\n```"),
                    title="Generated Exploit",
                    border_style="magenta"
                ))
                
                # Generate mitigations
                mitigations = self.exploit_generator.suggest_mitigations(vuln)
                self.console.print(Panel(
                    Markdown(mitigations),
                    title="Suggested Mitigations",
                    border_style="green"
                ))
                
                # Save exploit to file
                exploit_file = f"exploit_{vuln['type']}.py"
                with open(exploit_file, "w") as f:
                    f.write(exploit_code)
                self.console.print(f"[green]Exploit saved to {exploit_file}[/green]")
    
    def start_api_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the API server"""
        self.console.print(f"[bold green]Starting API server on {host}:{port}[/bold green]")
        uvicorn.run(app, host=host, port=port)
    
    def generate_report(self, results: Dict, output_format: str = "markdown"):
        """Generate analysis report"""
        if output_format == "markdown":
            with open("reloadai_report.md", "w") as f:
                f.write("# REloadAI Analysis Report\n\n")
                
                # File info
                f.write("## File Information\n")
                for key, value in results.get('file_info', {}).items():
                    f.write(f"- **{key}**: {value}\n")
                
                # Protections
                f.write("\n## Security Protections\n")
                for key, value in results.get('protections', {}).items():
                    f.write(f"- **{key.upper()}**: {value}\n")
                
                # Vulnerabilities
                if 'vulnerabilities' in results:
                    f.write("\n## Vulnerabilities\n")
                    for vuln in results['vulnerabilities']:
                        f.write(f"### {vuln['type']}\n")
                        f.write(f"- Function: {vuln.get('function', 'unknown')}\n")
                        f.write(f"- Reason: {vuln.get('reason', 'No details')}\n\n")
            
            self.console.print("[green]Report saved to reloadai_report.md[/green]")

def main():
    parser = argparse.ArgumentParser(description="REloadAI - Automated Binary Analysis & Exploit Generation")
    parser.add_argument("-f", "--file", help="Binary file to analyze")
    parser.add_argument("-l", "--license", help="License key for authentication")
    parser.add_argument("--api", action="store_true", help="Start API server")
    parser.add_argument("--host", default="0.0.0.0", help="API host address")
    parser.add_argument("--port", type=int, default=8000, help="API port")
    parser.add_argument("--features", nargs="+", help="Features to use", 
                       default=["basic_analysis", "string_extraction", "function_analysis"])
    parser.add_argument("--report", action="store_true", help="Generate analysis report")
    
    args = parser.parse_args()
    
    reload_ai = REloadAI()
    reload_ai.setup(args.license)
    
    if args.api:
        reload_ai.start_api_server(args.host, args.port)
    elif args.file:
        results = reload_ai.analyze_file(args.file, args.features)
        
        if args.report:
            reload_ai.generate_report(results)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()