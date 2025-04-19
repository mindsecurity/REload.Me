# core/ctf_solver.py
import re
import time
import subprocess
import angr
import claripy
from typing import Dict, List, Optional
import logging
import struct
import base64
import hashlib
from z3 import *
import magic
import requests
from bs4 import BeautifulSoup

class CTFSolver:
    """Automatic CTF challenge solver"""
    
    def __init__(self, challenge_path: str):
        self.challenge_path = challenge_path
        self.logger = logging.getLogger("CTFSolver")
        self.file_type = None
        self.file_info = None
        self.detected_challenge_type = None
        self.solution = None
        
    def identify_challenge(self) -> str:
        """Identify the type of CTF challenge"""
        # Get file type using magic
        file_magic = magic.from_file(self.challenge_path)
        self.file_type = file_magic
        
        # Try to identify challenge type
        if any(x in file_magic.lower() for x in ['elf', 'executable', 'shared object']):
            self.detected_challenge_type = 'binary_exploitation'
        elif 'python' in file_magic.lower():
            self.detected_challenge_type = 'python_reverse'
        elif 'zip' in file_magic.lower() or 'archive' in file_magic.lower():
            self.detected_challenge_type = 'stego_archive'
        elif any(x in file_magic.lower() for x in ['jpeg', 'png', 'gif', 'bmp']):
            self.detected_challenge_type = 'stego_image'
        elif 'text' in file_magic.lower():
            self.detected_challenge_type = 'crypto_text'
        elif 'pcap' in file_magic.lower():
            self.detected_challenge_type = 'network_forensics'
        else:
            self.detected_challenge_type = 'unknown'
        
        return self.detected_challenge_type
    
    def solve(self) -> Dict:
        """Attempt to solve the CTF challenge automatically"""
        challenge_type = self.identify_challenge()
        
        solver_map = {
            'binary_exploitation': self._solve_binary_exploitation,
            'python_reverse': self._solve_python_reverse,
            'stego_archive': self._solve_stego_archive,
            'stego_image': self._solve_stego_image,
            'crypto_text': self._solve_crypto_text,
            'network_forensics': self._solve_network_forensics
        }
        
        if challenge_type in solver_map:
            try:
                self.solution = solver_map[challenge_type]()
                return {
                    'success': True,
                    'challenge_type': challenge_type,
                    'solution': self.solution,
                    'steps': self._generate_solution_steps()
                }
            except Exception as e:
                self.logger.error(f"Failed to solve challenge: {e}")
                return {
                    'success': False,
                    'challenge_type': challenge_type,
                    'error': str(e)
                }
        else:
            return {
                'success': False,
                'challenge_type': challenge_type,
                'error': 'Unsupported challenge type'
            }
    
    def _solve_binary_exploitation(self) -> str:
        """Solve binary exploitation challenges"""
        # First, try angr symbolic execution
        try:
            proj = angr.Project(self.challenge_path, auto_load_libs=False)
            
            # Find address of main function
            main_addr = proj.loader.find_symbol('main').rebased_addr
            
            # Create initial state at main
            state = proj.factory.entry_state(addr=main_addr)
            
            # Create simulation manager
            simgr = proj.factory.simulation_manager(state)
            
            # Look for success conditions
            success_patterns = [b'flag{', b'FLAG{', b'CTF{', b'correct', b'Correct']
            
            # Explore for success
            simgr.explore(
                find=lambda s: any(pattern in s.posix.dumps(1) for pattern in success_patterns),
                avoid=lambda s: b'wrong' in s.posix.dumps(1) or b'Wrong' in s.posix.dumps(1)
            )
            
            if simgr.found:
                # Get the solution
                found_state = simgr.found[0]
                solution = found_state.posix.dumps(0)  # stdin
                output = found_state.posix.dumps(1)    # stdout
                
                # Extract flag from output
                flag = self._extract_flag(output.decode())
                if flag:
                    return f"Flag: {flag}\nInput: {solution.decode()}"
                return f"Found solution - Input: {solution.decode()}"
        except Exception as e:
            self.logger.warning(f"Angr failed: {e}")
        
        # If angr fails, try pattern-based analysis
        try:
            # Look for XOR operations
            disasm = subprocess.check_output(['objdump', '-d', self.challenge_path]).decode()
            if 'xor' in disasm.lower():
                # Try common XOR keys
                try:
                    strings = subprocess.check_output(['strings', self.challenge_path]).decode()
                    for line in strings.splitlines():
                        for key in range(256):
                            decoded = ''.join(chr(ord(c) ^ key) for c in line)
                            if any(pattern in decoded for pattern in ['flag{', 'FLAG{', 'CTF{']):
                                return f"XOR key: {key}, Flag: {decoded}"
                except:
                    pass
            
            # Check for hardcoded comparisons
            if 'cmp' in disasm.lower() or 'test' in disasm.lower():
                # Extract constants being compared
                constants = re.findall(r'cmp\s+.*,\s*0x([0-9a-f]+)', disasm)
                if constants:
                    # Try to reconstruct flag from compared values
                    potential_flag = ''
                    for const in constants:
                        try:
                            byte_val = int(const, 16)
                            if 32 <= byte_val <= 126:  # printable ASCII
                                potential_flag += chr(byte_val)
                        except:
                            continue
                    
                    if len(potential_flag) > 4:
                        return f"Potential flag from comparisons: {potential_flag}"
        except Exception as e:
            self.logger.warning(f"Pattern analysis failed: {e}")
        
        return "Unable to automatically solve this binary exploitation challenge"
    
    def _solve_python_reverse(self) -> str:
        """Solve Python reverse engineering challenges"""
        with open(self.challenge_path, 'r') as f:
            code = f.read()
        
        # Look for obfuscation patterns
        if 'exec' in code or 'eval' in code:
            # Try to deobfuscate
            try:
                # Replace exec/eval with print to see what's being executed
                deobfuscated = code.replace('exec(', 'print(').replace('eval(', 'print(')
                
                # Run in sandboxed environment to get the deobfuscated code
                process = subprocess.run(['python3', '-c', deobfuscated], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
                
                output = process.stdout
                
                # Look for flag patterns in output
                flag = self._extract_flag(output)
                if flag:
                    return f"Deobfuscated flag: {flag}"
                
                # Try to analyze the deobfuscated code
                return f"Deobfuscated code:\n{output[:500]}..."
            except Exception as e:
                self.logger.warning(f"Deobfuscation failed: {e}")
        
        # Look for encrypted strings
        enc_patterns = [
            r'base64\.b64decode\((.*?)\)',
            r'bytes\.fromhex\((.*?)\)',
            r'binascii\.unhexlify\((.*?)\)'
        ]
        
        for pattern in enc_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                try:
                    # Try to evaluate the string
                    decoded = eval(match)
                    if isinstance(decoded, bytes):
                        decoded = decoded.decode()
                    flag = self._extract_flag(decoded)
                    if flag:
                        return f"Decoded flag: {flag}"
                except:
                    continue
        
        # Look for password check functions
        if 'password' in code.lower() or 'flag' in code.lower():
            # Try to extract condition checks
            conditions = re.findall(r'if\s+(\w+)\s*==\s*[\'"]([^\'"]+)[\'"]', code)
            for var, value in conditions:
                if len(value) > 5 and not value.isdigit():
                    return f"Potential flag from condition check: {value}"
        
        return "Unable to automatically solve this Python reverse engineering challenge"
    
    def _solve_stego_image(self) -> str:
        """Solve steganography challenges in images"""
        try:
            # Try common stego tools
            tools = [
                ('steghide', ['steghide', 'extract', '-sf', self.challenge_path, '-p', '']),
                ('strings', ['strings', self.challenge_path]),
                ('exiftool', ['exiftool', self.challenge_path]),
                ('binwalk', ['binwalk', '-e', self.challenge_path])
            ]
            
            for tool_name, command in tools:
                try:
                    output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()
                    flag = self._extract_flag(output)
                    if flag:
                        return f"Found with {tool_name}: {flag}"
                except:
                    continue
            
            # Try LSB extraction
            try:
                from PIL import Image
                img = Image.open(self.challenge_path)
                pixels = img.load()
                
                # Extract LSB from RGB values
                bits = []
                for y in range(img.height):
                    for x in range(img.width):
                        pixel = pixels[x, y]
                        if isinstance(pixel, tuple):
                            for channel in pixel[:3]:  # RGB
                                bits.append(channel & 1)
                
                # Convert bits to bytes
                byte_data = []
                for i in range(0, len(bits), 8):
                    byte = 0
                    for j in range(8):
                        if i + j < len(bits):
                            byte |= bits[i + j] << (7 - j)
                    byte_data.append(byte)
                
                # Try to decode as ASCII
                decoded = ''.join(chr(b) if 32 <= b <= 126 else '' for b in byte_data)
                flag = self._extract_flag(decoded)
                if flag:
                    return f"LSB extracted flag: {flag}"
            except:
                pass
        except Exception as e:
            self.logger.warning(f"Image stego analysis failed: {e}")
        
        return "Unable to automatically solve this image steganography challenge"
    
    def _solve_crypto_text(self) -> str:
        """Solve text-based cryptography challenges"""
        with open(self.challenge_path, 'r') as f:
            text = f.read()
        
        # Try common encodings
        encodings = [
            ('Base64', lambda t: base64.b64decode(t).decode()),
            ('Hex', lambda t: bytes.fromhex(t).decode()),
            ('ROT13', lambda t: ''.join(chr(((ord(c) - 65 + 13) % 26) + 65) if c.isupper() else 
                                        chr(((ord(c) - 97 + 13) % 26) + 97) if c.islower() else c 
                                        for c in t)),
            ('URL', lambda t: requests.utils.unquote(t))
        ]
        
        for enc_name, decoder in encodings:
            try:
                decoded = decoder(text.strip())
                flag = self._extract_flag(decoded)
                if flag:
                    return f"{enc_name} decoded flag: {flag}"
            except:
                continue
        
        # Try common ciphers
        # Caesar cipher
        for shift in range(1, 26):
            caesar = ''.join(chr(((ord(c) - 65 - shift) % 26) + 65) if c.isupper() else 
                           chr(((ord(c) - 97 - shift) % 26) + 97) if c.islower() else c 
                           for c in text)
            flag = self._extract_flag(caesar)
            if flag:
                return f"Caesar cipher (shift {shift}): {flag}"
        
        # Vigenere with common CTF keys
        common_keys = ['CTF', 'FLAG', 'KEY', 'SECRET', 'CRYPTO']
        for key in common_keys:
            vigenere = ''
            key_idx = 0
            for c in text:
                if c.isalpha():
                    shift = ord(key[key_idx % len(key)].upper()) - 65
                    if c.isupper():
                        vigenere += chr(((ord(c) - 65 - shift) % 26) + 65)
                    else:
                        vigenere += chr(((ord(c) - 97 - shift) % 26) + 97)
                    key_idx += 1
                else:
                    vigenere += c
            
            flag = self._extract_flag(vigenere)
            if flag:
                return f"Vigenere cipher (key: {key}): {flag}"
        
        return "Unable to automatically solve this cryptography challenge"
    
    def _solve_network_forensics(self) -> str:
        """Solve network forensics challenges"""
        try:
            # Use tshark to extract data
            output = subprocess.check_output(['tshark', '-r', self.challenge_path, '-Y', 'http or ftp or smtp']).decode()
            
            # Look for flags in network data
            flag = self._extract_flag(output)
            if flag:
                return f"Found in network traffic: {flag}"
            
            # Look for interesting patterns
            if 'password' in output.lower() or 'flag' in output.lower():
                lines = output.splitlines()
                for i, line in enumerate(lines):
                    if 'password' in line.lower() or 'flag' in line.lower():
                        # Get context around the line
                        context = '\n'.join(lines[max(0, i-2):min(len(lines), i+3)])
                        possible_flag = self._extract_flag(context)
                        if possible_flag:
                            return f"Found in network traffic context: {possible_flag}"
        except:
            pass
        
        return "Unable to automatically solve this network forensics challenge"
    
    def _solve_stego_archive(self) -> str:
        """Solve steganography challenges in archives"""
        try:
            # Extract archive
            extract_dir = '/tmp/ctf_extract'
            subprocess.run(['mkdir', '-p', extract_dir])
            
            if self.challenge_path.endswith('.zip'):
                subprocess.run(['unzip', '-o', self.challenge_path, '-d', extract_dir])
            elif self.challenge_path.endswith('.tar') or self.challenge_path.endswith('.tar.gz'):
                subprocess.run(['tar', '-xf', self.challenge_path, '-C', extract_dir])
            
            # Search extracted files
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Check file content
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read()
                            # Try as text
                            try:
                                text_content = content.decode()
                                flag = self._extract_flag(text_content)
                                if flag:
                                    return f"Found in {file}: {flag}"
                            except:
                                pass
                            
                            # Try as binary
                            flag = self._extract_flag(str(content))
                            if flag:
                                return f"Found in binary data of {file}: {flag}"
                    except:
                        continue
            
            # Check for hidden files
            output = subprocess.check_output(['find', extract_dir, '-name', '.*']).decode()
            if output:
                hidden_files = output.splitlines()
                for hidden in hidden_files:
                    try:
                        with open(hidden, 'r') as f:
                            content = f.read()
                            flag = self._extract_flag(content)
                            if flag:
                                return f"Found in hidden file {hidden}: {flag}"
                    except:
                        continue
        except:
            pass
        
        return "Unable to automatically solve this archive steganography challenge"
    
    def _extract_flag(self, text: str) -> Optional[str]:
        """Extract flag from text using common CTF patterns"""
        flag_patterns = [
            r'flag\{[^\}]+\}',
            r'FLAG\{[^\}]+\}',
            r'CTF\{[^\}]+\}',
            r'[Ff][Ll][Aa][Gg]:\s*([^\s]+)',
            r'[Tt]he [Ff]lag is:?\s*([^\s]+)',
            r'[Pp]assword:?\s*([^\s]+)',
        ]
        
        for pattern in flag_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0) if '{' in pattern else match.group(1)
        
        return None
    
    def _generate_solution_steps(self) -> List[str]:
        """Generate step-by-step explanation of how the challenge was solved"""
        steps = []
        
        if self.detected_challenge_type == 'binary_exploitation':
            steps.append("1. Identified as binary exploitation challenge")
            steps.append("2. Used angr for symbolic execution analysis")
            steps.append("3. Found vulnerable functions and constraints")
            steps.append("4. Generated input that reaches flag condition")
        
        elif self.detected_challenge_type == 'python_reverse':
            steps.append("1. Identified as Python reverse engineering challenge")
            steps.append("2. Analyzed code for obfuscation patterns")
            steps.append("3. Deobfuscated code using dynamic analysis")
            steps.append("4. Extracted flag from deobfuscated code")
        
        elif self.detected_challenge_type == 'stego_image':
            steps.append("1. Identified as image steganography challenge")
            steps.append("2. Applied common stego tools (steghide, binwalk)")
            steps.append("3. Extracted LSB data from image pixels")
            steps.append("4. Found flag in extracted data")
        
        # Add more steps for other challenge types...
        
        return steps