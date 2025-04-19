import r2pipe
import json
import os
import subprocess
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import openai
from .utils import logger, get_file_format
from .output import generate_markdown, generate_pdf, generate_learning_doc


class BinaryAnalyzer:
    """Main binary analysis class using radare2 and GPT."""
    
    def __init__(self, binary_path: str, openai_key: str):
        self.binary_path = binary_path
        self.filename = Path(binary_path).name
        self.r2 = r2pipe.open(binary_path)
        
        # Initialize OpenAI client
        openai.api_key = openai_key
        
        # Analysis results storage
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
    
    def analyze_file_info(self) -> Dict:
        """Get basic file information."""
        info = self.r2.cmdj('ij')
        arch = info.get('bin', {}).get('arch', 'unknown')
        bits = info.get('bin', {}).get('bits', 0)
        format = info.get('bin', {}).get('bintype', 'unknown')
        
        self.results['file_info'] = {
            'name': self.filename,
            'path': self.binary_path,
            'arch': arch,
            'bits': bits,
            'format': format,
            'compiler': info.get('bin', {}).get('compiler', 'unknown')
        }
        
        return self.results['file_info']
    
    def analyze_security_features(self) -> Dict:
        """Run security checks on the binary."""
        checksec = self.r2.cmdj('iS')
        
        # Extract security features
        nx = 'NX enabled' if 'NX enabled' in str(checksec) else 'NX disabled'
        pie = 'PIE enabled' if 'PIE enabled' in str(checksec) else 'PIE disabled'
        canary = 'Stack canary found' if 'canary' in str(checksec).lower() else 'No stack canary'
        relro = 'Full RELRO' if 'full relro' in str(checksec).lower() else 'Partial RELRO' if 'partial relro' in str(checksec).lower() else 'No RELRO'
        
        self.results['checksec'] = {
            'nx': nx,
            'pie': pie,
            'canary': canary,
            'relro': relro
        }
        
        return self.results['checksec']
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract and analyze interesting strings from the binary."""
        strings = self.r2.cmdj(f'izj~{{.string}}')
        
        suspicious_patterns = [
            r'password',
            r'key',
            r'token',
            r'rand|random',
            r'crypto',
            r'decrypt|encrypt',
            r'secret',
            r'admin',
            r'root',
            r'exec|system|eval',
            r'cmd|command'
        ]
        
        self.results['strings'] = []
        for string in strings:
            if len(string) >= min_length:
                for pattern in suspicious_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        self.results['strings'].append({
                            'string': string,
                            'pattern': pattern
                        })
                        break
        
        return self.results['strings']
    
    def analyze_functions(self) -> Dict:
        """Get list of functions and their characteristics."""
        self.r2.cmd('aaa')  # Analyze all
        functions = self.r2.cmdj('aflj')
        
        for func in functions:
            self.results['functions'][func['name']] = {
                'address': func['offset'],
                'size': func['size'],
                'calls': func.get('calls', []),
                'called_by': func.get('called_by', [])
            }
        
        return self.results['functions']
    
    def analyze_main_function(self) -> Tuple[Dict, str]:
        """Perform detailed analysis of the main function."""
        # Find main function
        main_addr = None
        for func in self.results['functions']:
            if 'main' in func.lower():
                main_addr = self.results['functions'][func]['address']
                break
        
        if not main_addr:
            return {}, ""
        
        # Get disassembly of main function
        self.r2.cmd(f's {main_addr}')
        disasm = self.r2.cmd('pdf')
        
        # Use GPT to explain the disassembly
        prompt = f"""
        Analyze this x86/x64 assembly code from the main function and provide:
        1. Step-by-step explanation of what the code does
        2. Identify any security vulnerabilities (buffer overflows, format strings, etc)
        3. Explain any cryptographic or random number operations
        4. Provide pseudocode representation
        
        Assembly:
        {disasm}
        """
        
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert in x86/x64 assembly and reverse engineering. Provide detailed technical analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            
            analysis = response.choices[0].message.content
            
            self.results['main_analysis'] = {
                'address': main_addr,
                'disassembly': disasm,
                'gpt_analysis': analysis
            }
            
            return self.results['main_analysis'], disasm
            
        except Exception as e:
            logger.error(f"GPT analysis failed: {e}")
            return {'error': str(e)}, disasm
    
    def generate_exploit(self, disasm: str) -> Optional[str]:
        """Generate an exploit if certain patterns are found."""
        if not disasm:
            return None
            
        # Check for rand() or random operations
        if 'rand' in disasm.lower():
            prompt = f"""
            Based on this disassembly which contains random number operations, generate a C exploit code that:
            1. Predicts or breaks the randomness
            2. Exploits any weaknesses in the cryptographic implementation
            3. Includes comments explaining each step
            
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
                
                # Save exploit to file
                exploit_path = f"exploits/{self.filename}_exploit.c"
                os.makedirs("exploits", exist_ok=True)
                with open(exploit_path, 'w') as f:
                    f.write(exploit_code)
                
                return exploit_code
                
            except Exception as e:
                logger.error(f"Exploit generation failed: {e}")
                return None
        
        return None
    
    def generate_insights(self) -> List[str]:
        """Generate key insights from the analysis."""
        insights = []
        
        # Check security features
        if 'NX disabled' in self.results['checksec']['nx']:
            insights.append("⚠️ Binary has NX disabled - stack is executable which allows shellcode execution")
        
        if 'No stack canary' in self.results['checksec']['canary']:
            insights.append("⚠️ No stack canary found - vulnerable to buffer overflow attacks")
        
        if 'PIE disabled' in self.results['checksec']['pie']:
            insights.append("📍 PIE is disabled - addresses are not randomized, making exploitation easier")
        
        # Check for interesting functions
        dangerous_funcs = ['strcpy', 'strcat', 'gets', 'sprintf', 'scanf']
        for func in self.results['functions']:
            if any(df in func.lower() for df in dangerous_funcs):
                insights.append(f"🚨 Dangerous function found: {func} - potential buffer overflow vulnerability")
        
        # Check main analysis for vulnerabilities
        if 'main_analysis' in self.results and 'gpt_analysis' in self.results['main_analysis']:
            if 'buffer overflow' in self.results['main_analysis']['gpt_analysis'].lower():
                insights.append("💣 Potential buffer overflow vulnerability detected in main function")
            
            if 'format string' in self.results['main_analysis']['gpt_analysis'].lower():
                insights.append("🖨️ Potential format string vulnerability detected")
            
            if 'rand' in self.results['main_analysis']['gpt_analysis'].lower():
                insights.append("🎲 Weak randomness detected - exploitation possible through seed prediction")
        
        self.results['insights'] = insights
        return insights
    
    def generate_learning_notes(self) -> List[Dict]:
        """Generate educational content for beginners."""
        notes = []
        
        # Explain architecture
        notes.append({
            'topic': 'Architecture',
            'explanation': f"This binary is {self.results['file_info']['bits']}-bit {self.results['file_info']['arch']} architecture. This affects:\n" +
                         f"- Register sizes ({self.results['file_info']['bits']} bits wide)\n" +
                         f"- Calling conventions (how functions pass parameters)\n" +
                         f"- Memory addresses (4 bytes for 32-bit, 8 bytes for 64-bit)"
        })
        
        # Explain security features
        security_explained = {
            'nx': "NX (No-eXecute) bit prevents code execution from stack/heap",
            'pie': "PIE (Position Independent Executable) randomizes memory addresses",
            'canary': "Stack canaries detect buffer overflows by placing guard values",
            'relro': "RELRO (Relocation Read-Only) makes GOT read-only after relocation"
        }
        
        for feature, status in self.results['checksec'].items():
            notes.append({
                'topic': f"Security Feature: {feature.upper()}",
                'explanation': f"{security_explained[feature]}\nStatus: {status}\n" +
                              f"Impact: {'🔴 Vulnerable' if 'disabled' in status or 'No' in status else '🟢 Protected'}"
            })
        
        # Explain main function analysis
        if 'main_analysis' in self.results and 'gpt_analysis' in self.results['main_analysis']:
            notes.append({
                'topic': 'Main Function Analysis',
                'explanation': self.results['main_analysis']['gpt_analysis']
            })
        
        self.results['learning_notes'] = notes
        return notes
    
    def run_full_analysis(self) -> Dict:
        """Run complete binary analysis workflow."""
        logger.info(f"Starting analysis of {self.filename}")
        
        # 1. Basic file info
        self.analyze_file_info()
        logger.info("File info analysis complete")
        
        # 2. Security features
        self.analyze_security_features()
        logger.info("Security feature analysis complete")
        
        # 3. Extract strings
        self.extract_strings()
        logger.info(f"Found {len(self.results['strings'])} suspicious strings")
        
        # 4. Function analysis
        self.analyze_functions()
        logger.info(f"Found {len(self.results['functions'])} functions")
        
        # 5. Main function detailed analysis
        main_analysis, disasm = self.analyze_main_function()
        logger.info("Main function analysis complete")
        
        # 6. Generate exploit if applicable
        exploit = self.generate_exploit(disasm)
        if exploit:
            logger.info("Exploit code generated")
        
        # 7. Generate insights
        insights = self.generate_insights()
        logger.info(f"Generated {len(insights)} insights")
        
        # 8. Generate learning notes
        learning = self.generate_learning_notes()
        logger.info(f"Generated {len(learning)} learning notes")
        
        # 9. Generate reports
        generate_markdown(self.results, f"REloadAI_{self.filename}_output.md")
        generate_learning_doc(self.results, f"REloadAI_{self.filename}_Aula.md")
        generate_pdf(self.results, f"REloadAI_{self.filename}_output.pdf")
        
        logger.info("Analysis complete! Reports generated.")
        
        return self.results