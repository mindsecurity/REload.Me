import r2pipe
import json
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import openai

# Assuming src.common.utils will have a logger, and constants will be handled.
# For now, direct logger usage will be simplified or use a placeholder.
# from src.common.logging import get_logger # Original from static_analyzer
# from src.common.constants import SAFE_TIMEOUT # Original from static_analyzer
# log = get_logger(__name__) # Original from static_analyzer

# Placeholder for logger until src.common.logging is fully integrated
def log_message(message):
    print(f"[static_analyzer_log] {message}")

SENSITIVE_CALLS = [
    "gets", "strcpy", "strncpy", "sprintf", "system", "scanf",
    "memcpy", "memcmp", "fgets", "strcmp", "rand", "malloc",
    "free", "ptrace", "mprotect"
]

# Placeholder for SAFE_TIMEOUT until src.common.constants is fully integrated
SAFE_TIMEOUT_VAL = 30

class BinaryAnalysisError(Exception):
    """Custom exception for analysis errors."""
    pass

class SecurityError(Exception):
    """Custom exception for security related errors."""
    pass

class BinaryAnalyzer:
    """Main binary analysis class using radare2 and GPT."""
    
    def __init__(self, binary_path: str, openai_key: str):
        self.binary_path = binary_path
        self.filename = Path(binary_path).name
        self.analysis_tool = "radare2"
        try:
            self.r2 = r2pipe.open(binary_path)
        except Exception as e:
            log_message(f"Failed to open r2pipe for {binary_path}: {e}")
            self.r2 = None
            self.analysis_tool = "ghidra"
            self._init_ghidra()
            if self.r2 is None:
                raise BinaryAnalysisError(f"r2pipe open failed: {e}")

        if openai_key:
            openai.api_key = openai_key
        else:
            # Optionally handle missing OpenAI key, e.g. by disabling GPT features
            log_message("OpenAI key not provided. GPT-dependent features will be unavailable.")
            # raise ValueError("OpenAI API key is required for BinaryAnalyzer")


        self.results = {
            'file_info': {},
            'checksec': {},
            'strings': [],
            'functions': {},
            'main_analysis': {},
            'exploit': None,
            'insights': [],
            'learning_notes': []
        }
        # self.log = log_message # Assigning the placeholder logger

    def _init_ghidra(self) -> None:
        """Placeholder for initializing a Ghidra fallback."""
        ghidra_home = os.getenv("GHIDRA_HOME")
        if not ghidra_home or not Path(ghidra_home).exists():
            log_message("Ghidra not found. Set GHIDRA_HOME to enable fallback analysis.")
            return
        # Fallback implementation would spawn Ghidra headless analysis here.
        log_message("Ghidra integration is not yet implemented.")

    def close(self):
        """Closes the r2pipe connection."""
        if self.r2:
            self.r2.quit()
            self.r2 = None

    def analyze_file_info(self) -> Dict:
        """Get basic file information."""
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        info = self.r2.cmdj('ij')
        if not info: raise BinaryAnalysisError("Failed to get file info from r2.")
        
        bin_info = info.get('bin', {})
        self.results['file_info'] = {
            'name': self.filename,
            'path': self.binary_path,
            'arch': bin_info.get('arch', 'unknown'),
            'bits': bin_info.get('bits', 0),
            'format': bin_info.get('bintype', 'unknown'),
            'compiler': bin_info.get('compiler', 'unknown')
        }
        return self.results['file_info']

    def analyze_security_features(self) -> Dict:
        """Run security checks on the binary."""
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        # iSj might be better if available, iS is text-based
        checksec_str = self.r2.cmd('iS') 
        if checksec_str is None: raise BinaryAnalysisError("Failed to get checksec info from r2.")

        nx = 'NX enabled' if 'nx true' in checksec_str else 'NX disabled'
        pie = 'PIE enabled' if 'pic true' in checksec_str else 'PIE disabled' # pic often means PIE
        canary = 'Stack canary found' if 'canary true' in checksec_str else 'No stack canary'
        relro_str = ""
        if 'relro full' in checksec_str: relro_str = 'Full RELRO'
        elif 'relro partial' in checksec_str: relro_str = 'Partial RELRO'
        else: relro_str = 'No RELRO'
        
        self.results['checksec'] = {'nx': nx, 'pie': pie, 'canary': canary, 'relro': relro_str}
        return self.results['checksec']

    def extract_strings(self, min_length: int = 4) -> List[Dict]:
        """Extract and analyze interesting strings from the binary."""
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        strings_json = self.r2.cmdj(f'izzj') # izzj for JSON output of all strings
        
        if strings_json is None: 
            log_message("Failed to extract strings using izzj.")
            return []

        suspicious_patterns = [
            r'password', r'key', r'token', r'rand|random', r'crypto',
            r'decrypt|encrypt', r'secret', r'admin', r'root',
            r'exec|system|eval', r'cmd|command', r'flag', r'ctf'
        ]
        
        extracted_strings = []
        for s_obj in strings_json:
            string_val = s_obj.get('string', '')
            if len(string_val) >= min_length:
                for pattern in suspicious_patterns:
                    if re.search(pattern, string_val, re.IGNORECASE):
                        extracted_strings.append({'string': string_val, 'pattern': pattern, 'address': s_obj.get('vaddr')})
                        break
        self.results['strings'] = extracted_strings
        return self.results['strings']

    def analyze_functions(self) -> Dict:
        """Get list of functions and their characteristics."""
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        self.r2.cmd('aaa')  # Analyze all
        functions_json = self.r2.cmdj('aflj')
        if functions_json is None: raise BinaryAnalysisError("Failed to analyze functions.")

        self.results['functions'] = {}
        for func in functions_json:
            self.results['functions'][func['name']] = {
                'address': func['offset'],
                'size': func['size'],
                'calls': func.get('callrefs', []), # aflj uses 'callrefs' for calls made by function
                'called_by': func.get('coderefs', []) # 'coderefs' for calls to this function
            }
        return self.results['functions']

    def analyze_main_function(self) -> Tuple[Dict, str]:
        """Perform detailed analysis of the main function."""
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        if not self.results['functions']: self.analyze_functions()

        main_addr = None
        main_func_name = 'main' # Default
        for func_name, func_data in self.results['functions'].items():
            if 'main' in func_name.lower(): # More robust main detection
                main_addr = func_data['address']
                main_func_name = func_name
                break
        
        if not main_addr and self.results['functions']: # Fallback to first function if main not found
            first_func_name = list(self.results['functions'].keys())[0]
            main_addr = self.results['functions'][first_func_name]['address']
            main_func_name = first_func_name
            log_message(f"Main function not found, analyzing first function: {main_func_name}")
        
        if not main_addr: return {}, ""

        self.r2.cmd(f's {main_addr}')
        disasm = self.r2.cmd('pdf')
        if disasm is None: disasm = "Failed to get disassembly."

        # Use GPT to explain the disassembly
        prompt = f"""
        Analyze this x86/x64 assembly code from the function '{main_func_name}' and provide:
        1. Step-by-step explanation of what the code does.
        2. Identify any security vulnerabilities (buffer overflows, format strings, etc.).
        3. Explain any cryptographic or random number operations.
        4. Provide pseudocode representation.
        
        Assembly:
        {disasm}
        """
        analysis_content = "GPT analysis disabled or failed."
        if openai.api_key:
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4", # Consider making model configurable
                    messages=[
                        {"role": "system", "content": "You are an expert in x86/x64 assembly and reverse engineering. Provide detailed technical analysis."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2
                )
                analysis_content = response.choices[0].message.content
            except Exception as e:
                log_message(f"GPT analysis failed: {e}")
                analysis_content = f"GPT analysis error: {e}"
        
        self.results['main_analysis'] = {
            'name': main_func_name, 'address': main_addr,
            'disassembly': disasm, 'gpt_analysis': analysis_content
        }
        return self.results['main_analysis'], disasm

    def generate_exploit(self, disasm: str) -> Optional[str]:
        """Generate an exploit if certain patterns are found."""
        if not disasm or not openai.api_key: return None
            
        if 'rand' in disasm.lower(): # Simplified condition
            prompt = f"""
            Based on this disassembly which contains random number operations, generate a C exploit code that:
            1. Predicts or breaks the randomness.
            2. Exploits any weaknesses in the cryptographic implementation.
            3. Includes comments explaining each step.
            
            Assembly:
            {disasm}
            """
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are an expert in exploit development. Generate working exploit code."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.2
                )
                exploit_code = response.choices[0].message.content
                self.results['exploit'] = exploit_code
                
                exploit_dir = Path("exploits")
                exploit_dir.mkdir(exist_ok=True)
                exploit_path = exploit_dir / f"{self.filename}_exploit.c"
                with open(exploit_path, 'w') as f: f.write(exploit_code)
                return exploit_code
            except Exception as e:
                log_message(f"Exploit generation failed: {e}")
        return None

    def generate_insights(self) -> List[str]:
        insights = []
        if 'NX disabled' in self.results.get('checksec', {}).get('nx', ''):
            insights.append("⚠️ Binary has NX disabled - stack is executable which allows shellcode execution")
        # ... (add more insights as in the original class) ...
        self.results['insights'] = insights
        return insights

    def generate_learning_notes(self) -> List[Dict]:
        notes: List[Dict] = []
        fi = self.results.get('file_info', {})
        if fi:
            notes.append({
                'topic': 'Architecture',
                'note': f"Binary '{fi.get('name')}' targets {fi.get('arch')}-{fi.get('bits')} which affects calling conventions and gadget availability."
            })

        cs = self.results.get('checksec', {})
        explanations = {
            'NX enabled': 'Non-executable stack makes shellcode injection harder.',
            'NX disabled': 'Executable stack allows direct shellcode execution.',
            'PIE enabled': 'Addresses are randomized each run; leaks are usually required.',
            'PIE disabled': 'Fixed addresses simplify ROP chains.',
            'Stack canary found': 'Canaries detect simple stack overflows.',
            'No stack canary': 'Lack of canaries means classic BoF attacks may succeed.',
            'Full RELRO': 'GOT is read-only; overwriting entries is difficult.',
            'Partial RELRO': 'Only part of GOT is protected.',
            'No RELRO': 'GOT overwrites are viable attack vectors.'
        }
        for feature, value in cs.items():
            explanation = explanations.get(value)
            if explanation:
                notes.append({'topic': f'security:{feature}', 'note': explanation})

        for s in self.results.get('strings', []):
            notes.append({
                'topic': 'string',
                'note': f"Suspicious string '{s.get('string')}' matches pattern '{s.get('pattern')}' and may reveal credentials, commands or flags."
            })

        self.results['learning_notes'] = notes
        return notes
    
    def run_full_analysis(self) -> Dict:
        log_message(f"Starting analysis of {self.filename}")
        self.analyze_file_info()
        log_message("File info analysis complete")
        self.analyze_security_features()
        log_message("Security feature analysis complete")
        self.extract_strings()
        log_message(f"Found {len(self.results['strings'])} suspicious strings")
        self.analyze_functions()
        log_message(f"Found {len(self.results['functions'])} functions")
        _, disasm = self.analyze_main_function() # disasm is from main_analysis
        log_message("Main function analysis complete")
        if openai.api_key:
            exploit = self.generate_exploit(disasm)
            if exploit: log_message("Exploit code generated")
        self.generate_insights()
        log_message(f"Generated {len(self.results['insights'])} insights")
        self.generate_learning_notes()
        log_message(f"Generated {len(self.results['learning_notes'])} learning notes")
        
        # Reporting generation commented out as .output module is not yet refactored/moved
        # from .output import generate_markdown, generate_pdf, generate_learning_doc (this import would fail)
        # generate_markdown(self.results, f"REloadAI_{self.filename}_output.md")
        # generate_learning_doc(self.results, f"REloadAI_{self.filename}_Aula.md")
        # generate_pdf(self.results, f"REloadAI_{self.filename}_output.pdf")
        log_message("Analysis complete! Reporting generation skipped for now.")
        return self.results

    # Integrating the original analyze_static function as a method
    def analyze_static_details(self, deep: bool = False) -> dict:
        if not self.r2: raise BinaryAnalysisError("r2pipe not initialized.")
        self.r2.cmd(f"e anal.timeout={SAFE_TIMEOUT_VAL}")

        result = {
            "functions": [], "main_disasm": "", "main_addr": None, "arch": None,
            "bits": None, "rop_gadgets": [], "sensitive_calls": [], "cfg": "",
        }
        try:
            self.r2.cmd("aa")
            funcs = self.r2.cmdj("aflj") or []
            if not funcs and deep:
                self.r2.cmd("e anal.depth=4")
                self.r2.cmd("aaa")
                funcs = self.r2.cmdj("aflj") or []

            result["functions"] = funcs
            binmeta = self.r2.cmdj("ij")["bin"]
            result["arch"] = binmeta.get("arch")
            result["bits"] = binmeta.get("bits")

            main_func_candidate = next((f for f in funcs if f.get("name", "").endswith("main")), None)
            if not main_func_candidate and funcs: main_func_candidate = funcs[0]

            if main_func_candidate:
                addr = main_func_candidate.get("offset") or main_func_candidate.get("addr")
                result["main_addr"] = addr
                self.r2.cmd(f"s {addr}")
                disasm = self.r2.cmd("pdf")
                result["main_disasm"] = disasm
                for call_name in SENSITIVE_CALLS:
                    if call_name in disasm:
                        result["sensitive_calls"].append(call_name)
            rop_gadgets_str = self.r2.cmd("/Rj 3")
            if rop_gadgets_str:
                try:
                    rop_json = json.loads(rop_gadgets_str)
                    result["rop_gadgets"] = [g["opcode"] for g in rop_json if "opcode" in g]
                except Exception as e:
                    log_message(f"Error parsing ROP gadgets JSON: {e}")
            result["cfg"] = self.r2.cmd("agCd")
        except Exception as e:
            log_message(f"Erro na análise estática detalhada: {e}")
        return result
