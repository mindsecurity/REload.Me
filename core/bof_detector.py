"""core.bof_detector – naive static heuristics for classic stack‑based BoF."""
import re, logging
from typing import List, Dict, Any
log = logging.getLogger(__name__)
DANGEROUS_FUNCS = {'gets','strcpy','sprintf','scanf','strncpy','memcpy','read'}
def scan_disasm(func_name:str, disasm:str)->List[Dict[str,Any]]:
    findings=[]
    for line in disasm.splitlines():
        if any(f"call sym.imp.{d}" in line or f"call {d}" in line for d in DANGEROUS_FUNCS):
            addr=None
            m=re.match(r'\s*([0-9a-fA-F]+):', line)
            if m: addr=int(m.group(1),16)
            callee=next(d for d in DANGEROUS_FUNCS if d in line)
            findings.append({'function':func_name,'addr':addr,'dangerous_call':callee,'reason':f'unsafe {callee}'})
    return findings
