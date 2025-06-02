"""core.rop_generator – minimal search of common ROP gadgets via r2pipe."""
import r2pipe, logging
from typing import List
log=logging.getLogger(__name__)
G = ['pop rdi','pop rsi','pop rdx','pop rcx','ret']
def find_gadgets(binary:str)->List[int]:
    r2=r2pipe.open(binary, flags=['-2'])
    r2.cmd('aaa')
    addrs=[]
    for g in G:
        res=r2.cmdj(f'/Rj "{g}"') or []
        addrs.extend(x['offset'] for x in res)
    r2.quit()
    return addrs
