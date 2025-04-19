# core/analyzer.py
import r2pipe
import json
from typing import Dict, List, Optional

class BinaryAnalyzer:
    """Core binary analysis engine"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.r2 = None
        self.functions = []
        self.strings = []
        self.checksec_results = {}
    
    def connect(self):
        """Open connection to binary"""
        self.r2 = r2pipe.open(self.binary_path)
        self.r2.cmd('aaa')
    
    def get_file_info(self) -> Dict:
        """Get basic file information"""
        info = self.r2.cmdj('iIj')
        return {
            'format': info.get('bintype'),
            'arch': info.get('arch'),
            'bits': info.get('bits'),
            'os': info.get('os'),
            'class': info.get('class'),
        }
    
    def analyze_protections(self) -> Dict:
        """Analyze security protections"""
        checksec = self.r2.cmdj('ij').get('checksec', {})
        self.checksec_results = {
            'canary': checksec.get('canary', False),
            'nx': checksec.get('nx', False),
            'pic': checksec.get('pic', False),
            'relro': checksec.get('relro', 'none'),
            'fortify': checksec.get('fortify', False)
        }
        return self.checksec_results
    
    def extract_strings(self, min_length: int = 4) -> List[Dict]:
        """Extract interesting strings"""
        strings = self.r2.cmdj('izzj')
        self.strings = [s for s in strings if s['length'] >= min_length]
        
        # Flag strings as interesting if they contain keywords
        keywords = ['flag', 'key', 'secret', 'password', 'auth', 'token']
        for s in self.strings:
            s['interesting'] = any(kw in s['string'].lower() for kw in keywords)
        
        return self.strings
    
    def analyze_functions(self) -> List[Dict]:
        """Analyze all functions"""
        self.functions = self.r2.cmdj('aflj')
        
        # Enhance with vulnerability detection
        for func in self.functions:
            addr = func['offset']
            disasm = self.r2.cmd(f'pdf @ {addr}')
            
            # Basic vulnerability detection
            dangerous_calls = ['strcpy', 'gets', 'sprintf', 'scanf', 'system']
            func['vulnerabilities'] = []
            
            for call in dangerous_calls:
                if f'call sym.imp.{call}' in disasm:
                    func['vulnerabilities'].append({
                        'type': 'dangerous_function',
                        'function': call,
                        'reason': self._get_vuln_reason(call)
                    })
            
            # Check for crypto operations
            if 'rand' in disasm or 'srand' in disasm:
                func['vulnerabilities'].append({
                    'type': 'weak_crypto',
                    'function': 'rand/srand',
                    'reason': 'Uses predictable pseudorandom number generator'
                })
            
            # Basic format string detection
            if 'printf' in disasm and not '%s' in disasm and not '%d' in disasm:
                func['vulnerabilities'].append({
                    'type': 'format_string',
                    'function': 'printf',
                    'reason': 'Potentially uncontrolled format string'
                })
        
        return self.functions
    
    def _get_vuln_reason(self, function: str) -> str:
        """Get explanation for why a function is dangerous"""
        reasons = {
            'strcpy': 'No bounds checking - buffer overflow possible',
            'gets': 'Reads unbounded input - buffer overflow inevitable',
            'sprintf': 'No bounds checking on destination buffer',
            'scanf': 'Can overflow buffer with large input',
            'system': 'Command injection possible if input not sanitized'
        }
        return reasons.get(function, 'Function can be dangerous if used incorrectly')
    
    def get_main_function(self) -> Optional[Dict]:
        """Get the main function if it exists"""
        return next((f for f in self.functions if f['name'] == 'main'), None)
    
    def get_disassembly(self, function_addr: int) -> str:
        """Get disassembly for a specific function"""
        return self.r2.cmd(f'pdf @ {function_addr}')
    
    def close(self):
        """Close radare2 connection"""
        if self.r2:
            self.r2.quit()

