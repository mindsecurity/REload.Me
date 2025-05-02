# reloadai/core/fingerprints.py

import hashlib
import logging

log = logging.getLogger("fingerprints")

try:
    import ssdeep
except ImportError:
    ssdeep = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    import tlsh
except ImportError:
    tlsh = None


def ssdeep_hash(path: str) -> str | None:
    if not ssdeep:
        return None
    try:
        return ssdeep.hash_from_file(path)
    except Exception as e:
        log.warning(f"Erro ao gerar ssdeep: {e}")
        return None


def imphash(path: str) -> str | None:
    if not pefile:
        return None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        return pe.get_imphash()
    except Exception as e:
        log.debug(f"imphash falhou: {e}")
        return None


def tlsh_hash(path: str) -> str | None:
    if not tlsh:
        return None
    try:
        with open(path, "rb") as f:
            data = f.read()
        return tlsh.hash(data)
    except Exception as e:
        log.warning(f"Erro ao gerar TLSH: {e}")
        return None
