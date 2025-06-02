"""High-level pipeline orchestrating BoF detection and exploit skeleton."""
from typing import Dict, Any
from .bof_detector import scan_disasm
from src.modules.exploit_development.rop_generator import find_gadgets
class BoFPipeline:
    def __init__(self, r2, binary:str):
        self.r2=r2
        self.bin=binary
    def analyse(self, func_addr:int)->Dict[str,Any]:
        disasm=self.r2.cmd(f'pdf @ {func_addr}')
        findings=scan_disasm('target', disasm)
        gadgets=find_gadgets(self.bin)
        return {'findings':findings,'gadgets':gadgets,'disasm':disasm}
