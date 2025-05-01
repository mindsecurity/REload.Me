"""core.offset_finder – find exact offset to EIP/RIP using cyclic pattern helpers."""
import subprocess, shutil, logging, re
from typing import Optional
log=logging.getLogger(__name__)
def _generate_pattern(length:int=500)->str:
    pattern=""
    charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for a in charset[:52]:
        for b in charset[52:62]:
            for c in charset:
                if len(pattern)>=length:
                    return pattern
                pattern+=a+b+c
    return pattern[:length]
def offset(crash_value:str, length:int=500)->Optional[int]:
    pattern=_generate_pattern(length)
    idx=pattern.find(crash_value)
    if idx!=-1: return idx
    return None
