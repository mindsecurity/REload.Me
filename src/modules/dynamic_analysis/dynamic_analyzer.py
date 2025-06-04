# core/dynamic_analyzer.py
import docker
import subprocess
import os
import tempfile
import json
import time
from typing import Dict, List, Optional, Tuple
import logging
import unicorn
from unicorn.x86_const import *
from capstone import *
import frida

class DynamicAnalyzer:
    """Dynamic analysis engine that runs binary in sandboxed environment"""
    
    def __init__(self, binary_path: str, sandbox_type: str = "docker"):
        self.binary_path = binary_path
        self.sandbox_type = sandbox_type
        self.syscall_trace = []
        self.network_activity = []
        self.file_operations = []
        self.memory_allocations = []
        self.execution_log = []
        self.suspicious_behaviors = []
        self.logger = logging.getLogger("DynamicAnalyzer")
        
    def analyze(self, timeout: int = 30) -> Dict:
        """Run dynamic analysis"""
        if self.sandbox_type == "docker":
            return self._docker_analysis(timeout)
        elif self.sandbox_type == "unicorn":
            return self._unicorn_emulation(timeout)
        elif self.sandbox_type == "frida":
            return self._frida_tracing(timeout)
        else:
            raise ValueError(f"Unsupported sandbox type: {self.sandbox_type}")
    
    def _docker_analysis(self, timeout: int) -> Dict:
        """Run binary in Docker container"""
        try:
            client = docker.from_env()
            
            # Create secure container configuration
            container_config = {
                'image': 'reloadai/sandbox:ubuntu-latest',
                'command': f'/app/trace.sh /app/{os.path.basename(self.binary_path)}',
                'volumes': {self.binary_path: {'bind': f'/app/{os.path.basename(self.binary_path)}', 'mode': 'ro'}},
                'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges'],
                'network_disabled': False,  # Enable to monitor network
                'mem_limit': '512m',
                'cpu_period': 100000,
                'cpu_quota': 50000,  # 50% CPU
                'pids_limit': 100,
                'read_only': True,
            }
            
            # Run container
            self.logger.info("Starting analysis container...")
            container = client.containers.run(**container_config, detach=True)
            
            # Monitor execution
            start_time = time.time()
            try:
                while time.time() - start_time < timeout:
                    container.reload()  # refresh container status
                    if container.status in ("exited", "dead"):
                        break
                    time.sleep(0.1)
            except Exception:
                pass
            
            # Collect results
            logs = container.logs(stdout=True, stderr=True).decode()
            self.execution_log = logs.split('\n')
            
            # Parse syscalls from strace output
            self._parse_strace_output(logs)
            
            # Parse network activity from tcpdump
            self._parse_network_activity(logs)
            
            # Parse file operations
            self._parse_file_operations(logs)
            
            # Detect suspicious behaviors
            self._detect_suspicious_behaviors()
            
            # Cleanup
            container.stop()
            container.remove()
            
            return self._generate_report()
            
        except Exception as e:
            self.logger.error(f"Docker analysis failed: {e}")
            return {'error': str(e)}
    
    def _unicorn_emulation(self, timeout: int) -> Dict:
        """Emulate binary using Unicorn Engine"""
        try:
            # Load binary
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Initialize emulator (assuming x86-64)
            mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
            
            # Map memory regions
            code_base = 0x400000
            stack_base = 0x7fffff000000
            heap_base = 0x1000000
            
            mu.mem_map(code_base, 2 * 1024 * 1024)  # 2MB for code
            mu.mem_map(stack_base, 1 * 1024 * 1024)  # 1MB for stack
            mu.mem_map(heap_base, 10 * 1024 * 1024)  # 10MB for heap
            
            # Write binary to memory
            mu.mem_write(code_base, binary_data)
            
            # Set up stack
            mu.reg_write(UC_X86_REG_RSP, stack_base + 0x100000)
            mu.reg_write(UC_X86_REG_RBP, stack_base + 0x100000)
            
            # Hook syscalls
            def hook_syscall(uc, user_data):
                syscall_num = uc.reg_read(UC_X86_REG_RAX)
                self.syscall_trace.append({
                    'number': syscall_num,
                    'args': [
                        uc.reg_read(UC_X86_REG_RDI),
                        uc.reg_read(UC_X86_REG_RSI),
                        uc.reg_read(UC_X86_REG_RDX),
                        uc.reg_read(UC_X86_REG_R10),
                        uc.reg_read(UC_X86_REG_R8),
                        uc.reg_read(UC_X86_REG_R9)
                    ],
                    'timestamp': time.time()
                })
            
            mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
            
            # Hook memory access
            def hook_mem_access(uc, access, address, size, value, user_data):
                access_type = "READ" if access == UC_MEM_READ else "WRITE"
                self.memory_allocations.append({
                    'type': access_type,
                    'address': hex(address),
                    'size': size,
                    'value': value if access == UC_MEM_WRITE else None,
                    'timestamp': time.time()
                })
            
            mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
            
            # Start emulation
            try:
                mu.emu_start(code_base, code_base + len(binary_data), timeout=timeout * 1000000)
            except unicorn.UcError as e:
                self.logger.warning(f"Emulation error: {e}")
            
            # Detect suspicious behaviors
            self._detect_suspicious_behaviors()
            
            return self._generate_report()
            
        except Exception as e:
            self.logger.error(f"Unicorn emulation failed: {e}")
            return {'error': str(e)}
    
    def _frida_tracing(self, timeout: int) -> Dict:
        """Trace execution using Frida"""
        try:
            # Start process
            process = subprocess.Popen([self.binary_path], 
                                     stdin=subprocess.PIPE, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
            
            # Attach Frida
            session = frida.attach(process.pid)
            
            # Inject monitoring script
            script_code = """
            // Monitor syscalls
            Interceptor.attach(Module.findExportByName(null, "syscall"), {
                onEnter: function(args) {
                    send({
                        type: 'syscall',
                        number: args[0].toInt32(),
                        timestamp: Date.now()
                    });
                }
            });
            
            // Monitor network activity
            Interceptor.attach(Module.findExportByName(null, "socket"), {
                onEnter: function(args) {
                    send({
                        type: 'network',
                        operation: 'socket',
                        family: args[0],
                        type: args[1],
                        protocol: args[2],
                        timestamp: Date.now()
                    });
                }
            });
            
            // Monitor file operations
            Interceptor.attach(Module.findExportByName(null, "open"), {
                onEnter: function(args) {
                    send({
                        type: 'file',
                        operation: 'open',
                        path: Memory.readUtf8String(args[0]),
                        flags: args[1],
                        timestamp: Date.now()
                    });
                }
            });
            """
            
            script = session.create_script(script_code)
            
            # Message handler
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    if payload['type'] == 'syscall':
                        self.syscall_trace.append(payload)
                    elif payload['type'] == 'network':
                        self.network_activity.append(payload)
                    elif payload['type'] == 'file':
                        self.file_operations.append(payload)
            
            script.on('message', on_message)
            script.load()
            
            # Wait for execution
            time.sleep(timeout)
            
            # Cleanup
            try:
                process.terminate()
            except:
                pass
            
            session.detach()
            
            # Detect suspicious behaviors
            self._detect_suspicious_behaviors()
            
            return self._generate_report()
            
        except Exception as e:
            self.logger.error(f"Frida tracing failed: {e}")
            return {'error': str(e)}
    
    def _parse_strace_output(self, output: str):
        """Parse strace output for syscalls"""
        for line in output.split('\n'):
            if '(' in line and ')' in line:
                try:
                    syscall = line.split('(')[0].strip()
                    args = line.split('(')[1].split(')')[0].strip()
                    result = line.split('=')[-1].strip()
                    self.syscall_trace.append({
                        'syscall': syscall,
                        'args': args,
                        'result': result,
                        'timestamp': time.time()
                    })
                except:
                    continue
    
    def _parse_network_activity(self, output: str):
        """Parse tcpdump output for network activity"""
        # Simplified parsing - would need more sophisticated parsing for real use
        network_patterns = ['socket', 'connect', 'send', 'recv', 'bind', 'listen']
        for line in output.split('\n'):
            for pattern in network_patterns:
                if pattern in line.lower():
                    self.network_activity.append({
                        'type': pattern,
                        'details': line.strip(),
                        'timestamp': time.time()
                    })
    
    def _parse_file_operations(self, output: str):
        """Parse output for file operations"""
        file_patterns = ['open', 'read', 'write', 'close', 'unlink', 'chmod', 'mkdir']
        for line in output.split('\n'):
            for pattern in file_patterns:
                if pattern in line.lower():
                    self.file_operations.append({
                        'operation': pattern,
                        'details': line.strip(),
                        'timestamp': time.time()
                    })
    
    def _detect_suspicious_behaviors(self):
        """Detect suspicious patterns in execution"""
        # Check for anti-debugging
        if any('ptrace' in s.get('syscall', '') for s in self.syscall_trace):
            self.suspicious_behaviors.append({
                'type': 'anti_debugging',
                'description': 'Use of ptrace detected - possible anti-debugging technique',
                'severity': 'medium'
            })
        
        # Check for process hollowing
        if any('fork' in s.get('syscall', '') for s in self.syscall_trace) and \
           any('execve' in s.get('syscall', '') for s in self.syscall_trace):
            self.suspicious_behaviors.append({
                'type': 'process_hollowing',
                'description': 'Fork + execve pattern detected - possible process hollowing',
                'severity': 'high'
            })
        
        # Check for suspicious network activity
        if len(self.network_activity) > 0:
            suspicious_ports = [21, 22, 23, 25, 3389, 5900]  # FTP, SSH, Telnet, SMTP, RDP, VNC
            for activity in self.network_activity:
                details = activity.get('details', '')
                for port in suspicious_ports:
                    if str(port) in details:
                        self.suspicious_behaviors.append({
                            'type': 'suspicious_network',
                            'description': f'Connection to suspicious port {port} detected',
                            'severity': 'high',
                            'details': details
                        })
        
        # Check for privilege escalation attempts
        if any('setuid' in s.get('syscall', '') for s in self.syscall_trace) or \
           any('setgid' in s.get('syscall', '') for s in self.syscall_trace):
            self.suspicious_behaviors.append({
                'type': 'privilege_escalation',
                'description': 'Attempt to change process privileges detected',
                'severity': 'high'
            })
    
    def _generate_report(self) -> Dict:
        """Generate dynamic analysis report"""
        return {
            'syscall_trace': self.syscall_trace,
            'network_activity': self.network_activity,
            'file_operations': self.file_operations,
            'memory_allocations': self.memory_allocations,
            'execution_log': self.execution_log,
            'suspicious_behaviors': self.suspicious_behaviors,
            'summary': {
                'total_syscalls': len(self.syscall_trace),
                'network_events': len(self.network_activity),
                'file_operations': len(self.file_operations),
                'suspicious_behaviors_detected': len(self.suspicious_behaviors)
            }
        }