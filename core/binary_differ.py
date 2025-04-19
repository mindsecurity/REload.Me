# core/binary_differ.py
import r2pipe
import difflib
import json
import networkx as nx
from typing import Dict, List, Tuple, Set
import hashlib
import logging

class BinaryDiffer:
    """Compare two binary files for differences"""
    
    def __init__(self, binary1_path: str, binary2_path: str):
        self.binary1_path = binary1_path
        self.binary2_path = binary2_path
        self.r2_1 = None
        self.r2_2 = None
        self.logger = logging.getLogger("BinaryDiffer")
        
    def connect(self):
        """Open connections to both binaries"""
        self.r2_1 = r2pipe.open(self.binary1_path)
        self.r2_2 = r2pipe.open(self.binary2_path)
        
        # Perform complete analysis on both
        self.r2_1.cmd('aaa')
        self.r2_2.cmd('aaa')
    
    def diff(self) -> Dict:
        """Perform complete diff analysis"""
        if not self.r2_1 or not self.r2_2:
            self.connect()
        
        diff_results = {
            'metadata_diff': self._diff_metadata(),
            'functions_diff': self._diff_functions(),
            'strings_diff': self._diff_strings(),
            'protections_diff': self._diff_protections(),
            'code_diff': self._diff_code(),
            'graph_diff': self._diff_control_flow(),
            'vulnerability_diff': self._diff_vulnerabilities(),
            'summary': {}
        }
        
        # Generate summary
        diff_results['summary'] = self._generate_summary(diff_results)
        
        self.close()
        return diff_results
    
    def _diff_metadata(self) -> Dict:
        """Compare binary metadata"""
        info1 = self.r2_1.cmdj('iIj')
        info2 = self.r2_2.cmdj('iIj')
        
        differences = {}
        for key in set(info1.keys()) | set(info2.keys()):
            val1 = info1.get(key)
            val2 = info2.get(key)
            if val1 != val2:
                differences[key] = {'binary1': val1, 'binary2': val2}
        
        return differences
    
    def _diff_functions(self) -> Dict:
        """Compare functions between binaries"""
        funcs1 = {f['name']: f for f in self.r2_1.cmdj('aflj')}
        funcs2 = {f['name']: f for f in self.r2_2.cmdj('aflj')}
        
        # Find added, removed, and modified functions
        added = [f for f in funcs2.keys() if f not in funcs1]
        removed = [f for f in funcs1.keys() if f not in funcs2]
        
        modified = []
        for func_name in set(funcs1.keys()) & set(funcs2.keys()):
            func1 = funcs1[func_name]
            func2 = funcs2[func_name]
            
            # Compare size, offset, and complexity
            if func1['size'] != func2['size'] or \
               func1.get('cc', 0) != func2.get('cc', 0):  # Cyclomatic complexity
                modified.append({
                    'name': func_name,
                    'size_diff': func2['size'] - func1['size'],
                    'complexity_diff': func2.get('cc', 0) - func1.get('cc', 0),
                    'details': self._diff_function_code(func1['offset'], func2['offset'])
                })
        
        return {
            'added': added,
            'removed': removed,
            'modified': modified,
            'total_functions': {
                'binary1': len(funcs1),
                'binary2': len(funcs2)
            }
        }
    
    def _diff_function_code(self, addr1: int, addr2: int) -> Dict:
        """Compare the actual code of two functions"""
        disasm1 = self.r2_1.cmd(f'pdf @ {addr1}')
        disasm2 = self.r2_2.cmd(f'pdf @ {addr2}')
        
        # Generate line-by-line diff
        diff = list(difflib.unified_diff(
            disasm1.splitlines(),
            disasm2.splitlines(),
            fromfile='binary1',
            tofile='binary2',
            lineterm=''
        ))
        
        # Analyze instruction changes
        instructions1 = [line for line in disasm1.splitlines() if '│' in line and 'x' in line]
        instructions2 = [line for line in disasm2.splitlines() if '│' in line and 'x' in line]
        
        # Extract just the instruction parts
        insts1 = [line.split(' ')[-1] for line in instructions1]
        insts2 = [line.split(' ')[-1] for line in instructions2]
        
        # Calculate similarity
        matcher = difflib.SequenceMatcher(None, insts1, insts2)
        similarity = matcher.ratio()
        
        return {
            'diff': diff,
            'similarity': similarity,
            'instruction_changes': len(insts2) - len(insts1)
        }
    
    def _diff_strings(self) -> Dict:
        """Compare strings between binaries"""
        strings1 = set(s['string'] for s in self.r2_1.cmdj('izzj'))
        strings2 = set(s['string'] for s in self.r2_2.cmdj('izzj'))
        
        added = strings2 - strings1
        removed = strings1 - strings2
        
        # Find potential interesting strings
        interesting_keywords = ['flag', 'key', 'password', 'secret', 'token', 'auth', 'admin']
        interesting_added = [s for s in added if any(kw in s.lower() for kw in interesting_keywords)]
        interesting_removed = [s for s in removed if any(kw in s.lower() for kw in interesting_keywords)]
        
        return {
            'added': list(added),
            'removed': list(removed),
            'interesting_added': interesting_added,
            'interesting_removed': interesting_removed,
            'total_strings': {
                'binary1': len(strings1),
                'binary2': len(strings2)
            }
        }
    
    def _diff_protections(self) -> Dict:
        """Compare security protections"""
        info1 = self.r2_1.cmdj('ij')
        info2 = self.r2_2.cmdj('ij')
        
        checksec1 = info1.get('checksec', {})
        checksec2 = info2.get('checksec', {})
        
        changes = {}
        for protection in ['canary', 'nx', 'pic', 'relro', 'fortify']:
            val1 = checksec1.get(protection, False)
            val2 = checksec2.get(protection, False)
            if val1 != val2:
                changes[protection] = {
                    'binary1': val1,
                    'binary2': val2,
                    'change': 'enabled' if val2 and not val1 else 'disabled'
                }
        
        return changes
    
    def _diff_code(self) -> Dict:
        """Compare overall code sections"""
        sections1 = self.r2_1.cmdj('iSj')
        sections2 = self.r2_2.cmdj('iSj')
        
        # Create section mappings by name
        sects1 = {s['name']: s for s in sections1}
        sects2 = {s['name']: s for s in sections2}
        
        differences = {}
        for name in set(sects1.keys()) | set(sects2.keys()):
            s1 = sects1.get(name)
            s2 = sects2.get(name)
            
            if not s1:
                differences[name] = {'status': 'added'}
            elif not s2:
                differences[name] = {'status': 'removed'}
            elif s1['size'] != s2['size'] or s1.get('vaddr', 0) != s2.get('vaddr', 0):
                differences[name] = {
                    'status': 'modified',
                    'size_diff': s2['size'] - s1['size'],
                    'addr_diff': s2.get('vaddr', 0) - s1.get('vaddr', 0)
                }
        
        return differences
    
    def _diff_control_flow(self) -> Dict:
        """Compare control flow graphs"""
        # Get main function CFG as example
        main1 = next((f for f in self.r2_1.cmdj('aflj') if f['name'] == 'main'), None)
        main2 = next((f for f in self.r2_2.cmdj('aflj') if f['name'] == 'main'), None)
        
        if not main1 or not main2:
            return {'error': 'Main function not found in one or both binaries'}
        
        # Get CFG for each
        cfg1 = self.r2_1.cmdj(f'agfj @ {main1["offset"]}')
        cfg2 = self.r2_2.cmdj(f'agfj @ {main2["offset"]}')
        
        # Build networkx graphs
        g1 = nx.DiGraph()
        g2 = nx.DiGraph()
        
        # Add nodes and edges
        for block in cfg1:
            g1.add_node(block.get('offset', 0))
            for jump in block.get('jump', []):
                g1.add_edge(block.get('offset', 0), jump)
                
        for block in cfg2:
            g2.add_node(block.get('offset', 0))
            for jump in block.get('jump', []):
                g2.add_edge(block.get('offset', 0), jump)
        
        # Compare graph properties
        return {
            'nodes_diff': len(g2.nodes()) - len(g1.nodes()),
            'edges_diff': len(g2.edges()) - len(g1.edges()),
            'complexity_diff': nx.complexity.graph_clique_number(g2) - nx.complexity.graph_clique_number(g1),
            'cyclomatic_complexity': {
                'binary1': len(g1.edges()) - len(g1.nodes()) + 2,
                'binary2': len(g2.edges()) - len(g2.nodes()) + 2
            }
        }
    
    def _diff_vulnerabilities(self) -> Dict:
        """Compare potential vulnerabilities"""
        dangerous_functions = ['strcpy', 'gets', 'sprintf', 'scanf', 'system']
        
        vuln1 = self._find_vulnerabilities(self.r2_1)
        vuln2 = self._find_vulnerabilities(self.r2_2)
        
        # Compare vulnerability counts
        added_vulns = []
        removed_vulns = []
        
        for vuln_type in set(vuln1.keys()) | set(vuln2.keys()):
            count1 = len(vuln1.get(vuln_type, []))
            count2 = len(vuln2.get(vuln_type, []))
            
            if count2 > count1:
                added_vulns.append({
                    'type': vuln_type,
                    'count_diff': count2 - count1,
                    'locations': vuln2[vuln_type]
                })
            elif count1 > count2:
                removed_vulns.append({
                    'type': vuln_type,
                    'count_diff': count1 - count2,
                    'locations': vuln1[vuln_type]
                })
        
        return {
            'added_vulnerabilities': added_vulns,
            'removed_vulnerabilities': removed_vulns,
            'total_vulnerabilities': {
                'binary1': sum(len(v) for v in vuln1.values()),
                'binary2': sum(len(v) for v in vuln2.values())
            }
        }
    
    def _find_vulnerabilities(self, r2) -> Dict[str, List]:
        """Find potential vulnerabilities in a binary"""
        vulnerabilities = {}
        dangerous_functions = ['strcpy', 'gets', 'sprintf', 'scanf', 'system']
        
        # Search for dangerous function calls
        for func in dangerous_functions:
            calls = r2.cmd(f'/c sym.imp.{func}')
            if calls:
                vulnerabilities[func] = [addr.strip() for addr in calls.splitlines()]
        
        # Check for format string vulnerabilities
        format_strings = r2.cmd('/c printf')
        if format_strings:
            vulnerabilities['format_string'] = [addr.strip() for addr in format_strings.splitlines()]
        
        # Check for weak crypto
        crypto_funcs = ['rand', 'srand']
        for func in crypto_funcs:
            calls = r2.cmd(f'/c sym.imp.{func}')
            if calls:
                vulnerabilities[f'weak_crypto_{func}'] = [addr.strip() for addr in calls.splitlines()]
        
        return vulnerabilities
    
    def _generate_summary(self, diff_results: Dict) -> Dict:
        """Generate a summary of all differences"""
        summary = {
            'metadata_changes': len(diff_results['metadata_diff']),
            'functions': {
                'added': len(diff_results['functions_diff']['added']),
                'removed': len(diff_results['functions_diff']['removed']),
                'modified': len(diff_results['functions_diff']['modified'])
            },
            'strings': {
                'added': len(diff_results['strings_diff']['added']),
                'removed': len(diff_results['strings_diff']['removed']),
                'interesting_changes': len(diff_results['strings_diff']['interesting_added']) + 
                                     len(diff_results['strings_diff']['interesting_removed'])
            },
            'protection_changes': len(diff_results['protections_diff']),
            'vulnerability_changes': {
                'added': len(diff_results['vulnerability_diff']['added_vulnerabilities']),
                'removed': len(diff_results['vulnerability_diff']['removed_vulnerabilities'])
            },
            'overall_similarity': self._calculate_overall_similarity(diff_results)
        }
        
        return summary
    
    def _calculate_overall_similarity(self, diff_results: Dict) -> float:
        """Calculate overall similarity between binaries"""
        # Weight different aspects of similarity
        weights = {
            'functions': 0.4,
            'strings': 0.2,
            'code': 0.3,
            'metadata': 0.1
        }
        
        # Calculate individual similarities
        func_similarity = 1.0 - (
            len(diff_results['functions_diff']['added']) +
            len(diff_results['functions_diff']['removed']) +
            len(diff_results['functions_diff']['modified']) * 0.5
        ) / max(
            diff_results['functions_diff']['total_functions']['binary1'],
            diff_results['functions_diff']['total_functions']['binary2'],
            1
        )
        
        string_similarity = 1.0 - (
            len(diff_results['strings_diff']['added']) +
            len(diff_results['strings_diff']['removed'])
        ) / max(
            diff_results['strings_diff']['total_strings']['binary1'],
            diff_results['strings_diff']['total_strings']['binary2'],
            1
        )
        
        # Code similarity based on section changes
        code_changes = len(diff_results['code_diff'])
        code_similarity = 1.0 - (code_changes / max(10, code_changes))  # Normalize
        
        metadata_similarity = 1.0 - (len(diff_results['metadata_diff']) / 10.0)  # Normalize
        
        # Weighted average
        overall_similarity = (
            func_similarity * weights['functions'] +
            string_similarity * weights['strings'] +
            code_similarity * weights['code'] +
            metadata_similarity * weights['metadata']
        )
        
        return max(0.0, min(1.0, overall_similarity))
    
    def close(self):
        """Close radare2 connections"""
        if self.r2_1:
            self.r2_1.quit()
        if self.r2_2:
            self.r2_2.quit()