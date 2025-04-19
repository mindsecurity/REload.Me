# core/analyzer.py
import r2pipe
import json
import os
import re
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import shlex

class BinaryAnalysisError(Exception):
    """Erro durante análise de binário"""
    pass

class SecurityError(Exception):
    """Erro de segurança - acesso a arquivos não permitidos"""
    pass

class SecurityValidator:
    """Validador de segurança para análise de binários"""
    
    @staticmethod
    def validate_path(file_path: str) -> str:
        """Valida e sanitiza caminhos de arquivo"""
        # Resolve path absoluto e normaliza
        abs_path = os.path.abspath(file_path)
        
        # Verifica se o arquivo existe
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Binary {abs_path} not found")
        
        # Verifica se é um arquivo regular
        if not os.path.isfile(abs_path):
            raise ValueError(f"{abs_path} is not a regular file")
        
        # Verifica tamanho do arquivo
        file_size = os.path.getsize(abs_path)
        max_size = int(os.getenv('MAX_BINARY_SIZE', 50 * 1024 * 1024))  # 50MB default
        if file_size > max_size:
            raise ValueError(f"File too large: {file_size} bytes (max: {max_size})")
        
        return abs_path

class BinaryAnalyzer:
    """Core binary analysis engine"""
    
    def __init__(self, binary_path: str, debug: bool = False):
        # Validações de segurança
        self.validator = SecurityValidator()
        self.binary_path = self.validator.validate_path(binary_path)
        
        self.r2 = None
        self.functions = []
        self.strings = []
        self.checksec_results = {}
        self.max_functions = 1000  # Limite de funções para análise
        self.max_strings = 10000   # Limite de strings para análise
        self.debug = debug
    
    def connect(self) -> None:
        """Open connection to binary"""
        try:
            # Abre com flags corretas
            self.r2 = r2pipe.open(self.binary_path, flags=["-2"])
            
            # Configurações importantes primeiro
            self.r2.cmd('e anal.autoname=true')
            self.r2.cmd('e bin.relocs.apply=true')
            self.r2.cmd('e anal.strings=true')
            self.r2.cmd('e asm.functions=true')
            
            # Análise mais completa
            self.r2.cmd('aaa')  # Análise completa
            
            if self.debug:
                print("[DEBUG] Radare2 conectado e análise inicial concluída")
            
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to connect to binary: {str(e)}")
    
    def get_file_info(self) -> Dict[str, any]:
        """Get basic file information"""
        try:
            info = self.r2.cmdj('iIj')
            
            # Sanitiza output
            sanitized_info = {
                'format': self._sanitize_string(info.get('bintype', 'unknown')),
                'arch': self._sanitize_string(info.get('arch', 'unknown')),
                'bits': int(info.get('bits', 0)),
                'os': self._sanitize_string(info.get('os', 'unknown')),
                'class': self._sanitize_string(info.get('class', 'unknown')),
                'size': int(info.get('size', 0)),
                'timestamp': datetime.now().isoformat()
            }
            
            return sanitized_info
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to get file info: {str(e)}")
    
    def _sanitize_string(self, text: str) -> str:
        """Sanitiza strings para prevenir XSS e SQL injection"""
        if not isinstance(text, str):
            return str(text)
        
        # Remove caracteres especiais
        return re.sub(r'[<>\'"/\\]', '', text)[:1000]  # Limite de 1000 chars
    
    def analyze_protections(self) -> Dict[str, any]:
        """Analyze security protections"""
        try:
            # Tentativa 1: Usar comando iI (informações básicas)
            basic_info = self.r2.cmdj('iIj')
            
            # Tentativa 2: Usar comando específico do radare2
            security_info = self.r2.cmdj('ij')
            
            # Inicializa valores padrão
            self.checksec_results = {
                'canary': False,
                'nx': False,
                'pic': False,
                'relro': 'none',
                'fortify': False
            }
            
            # Verifica se temos informações de checksec
            if security_info and 'bin' in security_info:
                bin_info = security_info['bin']
                
                # Canary
                self.checksec_results['canary'] = bin_info.get('canary', False)
                
                # NX (No-Execute)
                self.checksec_results['nx'] = bin_info.get('nx', False)
                
                # PIC/PIE
                self.checksec_results['pic'] = bin_info.get('pic', False)
                
                # RELRO
                if bin_info.get('relro', False):
                    self.checksec_results['relro'] = 'full' if bin_info.get('relro_full', False) else 'partial'
            
            # Alternativa usando comandos diretos
            if not security_info or 'bin' not in security_info:
                # Verifica NX usando flags do binário
                nx_check = self.r2.cmd('i~nx')
                self.checksec_results['nx'] = 'true' in nx_check.lower()
                
                # Verifica PIE
                pie_check = self.r2.cmd('i~pic')
                self.checksec_results['pic'] = 'true' in pie_check.lower()
                
                # Verifica RELRO
                relro_check = self.r2.cmd('ir')
                if 'GNU_RELRO' in relro_check:
                    self.checksec_results['relro'] = 'partial' if 'BIND_NOW' not in relro_check else 'full'
                
                # Verifica Canary
                symbols = self.r2.cmd('is~__stack_chk_fail')
                self.checksec_results['canary'] = bool(symbols)
            
            return self.checksec_results
            
        except Exception as e:
            # Se tudo falhar, retorna valores padrão com erro logado
            print(f"Warning: Error analyzing protections: {str(e)}")
            return {
                'canary': False,
                'nx': False,
                'pic': False,
                'relro': 'none',
                'fortify': False
            }
    
    def analyze_functions(self) -> List[Dict[str, any]]:
        """Analyze all functions with safety limits"""
        try:
            # Lista todas as funções
            self.functions = self.r2.cmdj('aflj')[:self.max_functions]
            
            if self.debug:
                print(f"[DEBUG] Encontradas {len(self.functions)} funções")
            
            for func in self.functions:
                addr = func['offset']
                name = func.get('name', '')
                
                if self.debug:
                    print(f"[DEBUG] Analisando função: {name} @ {hex(addr)}")
                
                # Obtém disassembly da função
                disasm = self.r2.cmd(f'pdf @ {addr}')
                
                # Lista todas as chamadas de função no disassembly
                calls = self.r2.cmd(f'afl @ {addr}~call')
                
                # Lista imports
                imports = self.r2.cmd('ii~strcpy,gets,sprintf,scanf,system')
                
                # Basic vulnerability detection
                dangerous_calls = ['strcpy', 'gets', 'sprintf', 'scanf', 'system']
                func['vulnerabilities'] = []
                
                # Verifica cada tipo de vulnerabilidade
                for call in dangerous_calls:
                    # Verifica no disassembly
                    if f'call sym.imp.{call}' in disasm or f'call {call}' in disasm:
                        if self.debug:
                            print(f"[DEBUG] Encontrada chamada vulnerável: {call} em {name}")
                        func['vulnerabilities'].append({
                            'type': 'dangerous_function',
                            'function': call,
                            'reason': self._get_vuln_reason(call)
                        })
                    
                    # Verifica também nos imports
                    elif call in imports:
                        if self.debug:
                            print(f"[DEBUG] Encontrada importação vulnerável: {call}")
                        func['vulnerabilities'].append({
                            'type': 'dangerous_function',
                            'function': call,
                            'reason': self._get_vuln_reason(call)
                        })
                
                # Check for crypto operations
                if 'rand' in disasm or 'srand' in disasm:
                    if self.debug:
                        print(f"[DEBUG] Encontrada função de crypto fraca em {name}")
                    func['vulnerabilities'].append({
                        'type': 'weak_crypto',
                        'function': 'rand/srand',
                        'reason': 'Uses predictable pseudorandom number generator'
                    })
                
                # Basic format string detection
                if 'printf' in disasm and not re.search(r'%[dxscf]', disasm):
                    if self.debug:
                        print(f"[DEBUG] Possível format string em {name}")
                    func['vulnerabilities'].append({
                        'type': 'format_string',
                        'function': 'printf',
                        'reason': 'Potentially uncontrolled format string'
                    })
            
            return self.functions
            
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to analyze functions: {str(e)}")
    
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
    
    def get_main_function(self) -> Optional[Dict[str, any]]:
        """Get the main function if it exists"""
        return next((f for f in self.functions if f['name'] == 'main'), None)
    
    def get_disassembly(self, function_addr: int) -> str:
        """Get disassembly for a specific function with size limit"""
        try:
            return self.r2.cmd(f'pdf @ {function_addr}')
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to get disassembly: {str(e)}")
    
    def close(self) -> None:
        """Close radare2 connection"""
        if self.r2:
            try:
                self.r2.quit()
            except:
                pass  # Ignore errors on close
            finally:
                self.r2 = None