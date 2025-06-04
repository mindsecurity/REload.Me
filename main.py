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

from src.modules.static_analysis.static_analyzer import BinaryAnalyzer
from src.modules.exploit_development.exploit_generator import ExploitGenerator
from src.modules.dynamic_analysis.dynamic_analyzer import DynamicAnalyzer
from core.binary_differ import BinaryDiffer
from core.ctf_solver import CTFSolver
from core.cfg_visualizer import CFGVisualizer
from core.malware_generator import MalwareGenerator
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
    
    def dynamic_analysis(self, file_path: str, sandbox_type: str = "docker", timeout: int = 30) -> Dict:
        """Perform dynamic analysis on binary"""
        self.console.rule(f"[bold blue]Dynamic Analysis: {os.path.basename(file_path)}[/bold blue]")
        
        dynamic_analyzer = DynamicAnalyzer(file_path, sandbox_type)
        
        with self.console.status(f"[bold green]Running dynamic analysis in {sandbox_type} sandbox..."):
            results = dynamic_analyzer.analyze(timeout)
        
        if results.get('error'):
            self.console.print(f"[red]Error: {results['error']}[/red]")
            return results
        
        # Display results
        self._display_dynamic_analysis(results)
        
        return results
    
    def diff_binaries(self, binary1: str, binary2: str) -> Dict:
        """Compare two binaries for differences"""
        self.console.rule(f"[bold blue]Binary Diff: {os.path.basename(binary1)} vs {os.path.basename(binary2)}[/bold blue]")
        
        differ = BinaryDiffer(binary1, binary2)
        
        with self.console.status("[bold green]Analyzing differences..."):
            diff_results = differ.diff()
        
        self._display_diff_results(diff_results)
        
        return diff_results
    
    def solve_ctf(self, challenge_path: str) -> Dict:
        """Attempt to automatically solve CTF challenge"""
        self.console.rule(f"[bold blue]CTF Solver: {os.path.basename(challenge_path)}[/bold blue]")
        
        solver = CTFSolver(challenge_path)
        
        with self.console.status("[bold green]Analyzing challenge..."):
            result = solver.solve()
        
        self._display_ctf_solution(result)
        
        return result
    
    def visualize_cfg(self, file_path: str, function_name: str = "main", output_format: str = "html") -> str:
        """Generate 3D visualization of control flow graph"""
        self.console.rule(f"[bold blue]3D CFG Visualization: {os.path.basename(file_path)} - {function_name}[/bold blue]")
        
        visualizer = CFGVisualizer(file_path)
        
        with self.console.status("[bold green]Generating 3D visualization..."):
            output_file = visualizer.export_cfg(function_name, output_format)
        
        if output_file:
            self.console.print(f"[green]CFG visualization saved to {output_file}[/green]")
            return output_file
        else:
            self.console.print("[red]Failed to generate CFG visualization[/red]")
            return None
    
    def generate_malware(self, platform: str, payload_type: str, config: Dict, obfuscation: List[str] = None) -> Dict:
        """Generate custom malware for red team operations"""
        self.console.rule(f"[bold blue]Malware Generator: {platform} - {payload_type}[/bold blue]")
        
        generator = MalwareGenerator()
        
        with self.console.status("[bold green]Generating payload..."):
            result = generator.generate(platform, payload_type, config, obfuscation)
        
        if result.get('success'):
            self._display_malware_result(result)
        else:
            self.console.print(f"[red]Error: {result.get('error')}[/red]")
        
        return result
    
    def _display_dynamic_analysis(self, results: Dict):
        """Display dynamic analysis results"""
        summary = results.get('summary', {})
        
        table = Table(title="Dynamic Analysis Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Syscalls", str(summary.get('total_syscalls', 0)))
        table.add_row("Network Events", str(summary.get('network_events', 0)))
        table.add_row("File Operations", str(summary.get('file_operations', 0)))
        table.add_row("Suspicious Behaviors", str(summary.get('suspicious_behaviors_detected', 0)))
        
        self.console.print(table)
        
        # Display suspicious behaviors
        if results.get('suspicious_behaviors'):
            self.console.print("\n[bold red]Suspicious Behaviors Detected:[/bold red]")
            for behavior in results['suspicious_behaviors']:
                self.console.print(Panel(
                    f"[bold]{behavior['type']}[/bold]\n"
                    f"Description: {behavior['description']}\n"
                    f"Severity: {behavior['severity']}",
                    title=f"Suspicious Behavior",
                    border_style="red"
                ))
    
    def _display_diff_results(self, diff_results: Dict):
        """Display binary diff results"""
        summary = diff_results.get('summary', {})
        
        table = Table(title="Binary Diff Summary")
        table.add_column("Category", style="cyan")
        table.add_column("Changes", style="green")
        
        table.add_row("Metadata Changes", str(summary.get('metadata_changes', 0)))
        table.add_row("Functions Added", str(summary.get('functions', {}).get('added', 0)))
        table.add_row("Functions Removed", str(summary.get('functions', {}).get('removed', 0)))
        table.add_row("Functions Modified", str(summary.get('functions', {}).get('modified', 0)))
        table.add_row("Protection Changes", str(summary.get('protection_changes', 0)))
        table.add_row("Overall Similarity", f"{summary.get('overall_similarity', 0):.2%}")
        
        self.console.print(table)
        
        # Display protection changes
        if diff_results.get('protections_diff'):
            self.console.print("\n[bold yellow]Protection Changes:[/bold yellow]")
            for protection, change in diff_results['protections_diff'].items():
                self.console.print(f"• {protection}: {change['binary1']} → {change['binary2']} ({change['change']})")
    
    def _display_ctf_solution(self, result: Dict):
        """Display CTF solution result"""
        if result.get('success'):
            self.console.print(Panel(
                f"[bold green]Challenge Solved![/bold green]\n"
                f"Type: {result.get('challenge_type')}\n"
                f"Solution: {result.get('solution')}",
                title="CTF Solution",
                border_style="green"
            ))
            
            if result.get('steps'):
                self.console.print("\n[bold cyan]Solution Steps:[/bold cyan]")
                for step in result['steps']:
                    self.console.print(f"• {step}")
        else:
            self.console.print(Panel(
                f"[bold red]Failed to solve challenge[/bold red]\n"
                f"Type: {result.get('challenge_type')}\n"
                f"Error: {result.get('error')}",
                title="CTF Failure",
                border_style="red"
            ))
    
    def _display_malware_result(self, result: Dict):
        """Display malware generation result"""
        self.console.print(Panel(
            f"[bold green]Malware Generated Successfully[/bold green]\n"
            f"Platform: {result.get('platform')}\n"
            f"Payload Type: {result.get('payload_type')}\n"
            f"Obfuscation: {', '.join(result.get('obfuscation', []))}",
            title="Malware Generation Result",
            border_style="green"
        ))
        
        if result.get('binary_path'):
            self.console.print(f"\n[cyan]Binary saved to: {result['binary_path']}[/cyan]")
        
        # Save payload code to file
        with open(f"payload_{result['platform']}_{result['payload_type']}.c", "w") as f:
            f.write(result['payload_code'])
        
        self.console.print(f"[cyan]Payload code saved to: payload_{result['platform']}_{result['payload_type']}.c[/cyan]")
    
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
    parser = argparse.ArgumentParser(description="REloadAI v2.0 - Automated Binary Analysis & Exploit Generation")
    parser.add_argument("-f", "--file", help="Binary file to analyze")
    parser.add_argument("-l", "--license", help="License key for authentication")
    parser.add_argument("--api", action="store_true", help="Start API server")
    parser.add_argument("--host", default="0.0.0.0", help="API host address")
    parser.add_argument("--port", type=int, default=8000, help="API port")
    parser.add_argument("--features", nargs="+", help="Features to use", 
                       default=["basic_analysis", "string_extraction", "function_analysis"])
    parser.add_argument("--report", action="store_true", help="Generate analysis report")
    
    # New arguments for new features
    parser.add_argument("--dynamic", action="store_true", help="Perform dynamic analysis")
    parser.add_argument("--sandbox", choices=["docker", "unicorn", "frida"], default="docker", 
                       help="Sandbox type for dynamic analysis")
    parser.add_argument("--diff", nargs=2, metavar=("BINARY1", "BINARY2"), 
                       help="Compare two binaries")
    parser.add_argument("--ctf", help="Attempt to solve CTF challenge")
    parser.add_argument("--cfg", help="Generate 3D CFG visualization")
    parser.add_argument("--function", default="main", help="Function name for CFG visualization")
    parser.add_argument("--malware", action="store_true", help="Generate custom malware")
    parser.add_argument("--platform", choices=["windows", "linux", "macos"], default="windows", 
                       help="Target platform for malware")
    parser.add_argument("--payload", choices=["reverse_shell", "bind_shell", "meterpreter", "command_exec", "file_download"], 
                       default="reverse_shell", help="Payload type for malware")
    parser.add_argument("--obfuscate", nargs="+", choices=["xor", "base64", "aes", "polymorphic", "metamorphic"], 
                       help="Obfuscation techniques for malware")
    parser.add_argument("--lhost", default="127.0.0.1", help="LHOST for reverse shell")
    parser.add_argument("--lport", type=int, default=4444, help="LPORT for reverse shell")
    
    args = parser.parse_args()
    
    reload_ai = REloadAI()
    reload_ai.setup(args.license)
    
    if args.api:
        reload_ai.start_api_server(args.host, args.port)
    elif args.file:
        results = reload_ai.analyze_file(args.file, args.features)
        
        if args.dynamic:
            reload_ai.dynamic_analysis(args.file, args.sandbox)
        
        if args.cfg:
            reload_ai.visualize_cfg(args.file, args.function)
        
        if args.report:
            reload_ai.generate_report(results)
    elif args.diff:
        reload_ai.diff_binaries(args.diff[0], args.diff[1])
    elif args.ctf:
        reload_ai.solve_ctf(args.ctf)
    elif args.malware:
        config = {
            'lhost': args.lhost,
            'lport': args.lport
        }
        reload_ai.generate_malware(args.platform, args.payload, config, args.obfuscate)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
