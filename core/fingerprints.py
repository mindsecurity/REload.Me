
"""core.fingerprints – compute ssdeep & imphash if libs present"""

import logging, os
log = logging.getLogger("fingerprints")
try:
    import ssdeep as _ssdeep
except ImportError:
    _ssdeep = None
try:
    import pefile as _pefile
except ImportError:
    _pefile = None

def ssdeep_hash(path: str)->str|None:
    if _ssdeep is None:
        return None
    try:
        return _ssdeep.hash_from_file(path)
    except Exception as e:
        log.debug("ssdeep failed: %s", e)
        return None

def imphash(path: str)->str|None:
    if _pefile is None:
        return None
    try:
        pe = _pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        return pe.get_imphash()
    except Exception as e:
        log.debug("imphash failed: %s", e)
        return None
