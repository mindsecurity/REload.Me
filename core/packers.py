import subprocess
import logging
import os
from typing import List

log = logging.getLogger("packers")

COMMON_PACKERS = [
    "upx", "asp", "themida", "nsis", "petite", "mpress", "fsg", "upack", "enigma",
    "telock", "armadillo", "y0da", "pecompact", "pebundle", "aspack", "bangcle"
]

def detect(path: str) -> List[str]:
    """
    Tenta detectar packers comuns via strings e binwalk.
    Retorna uma lista de nomes de packers detectados.
    """
    detected = []

    try:
        # Tenta detectar via strings
        output = subprocess.check_output(["strings", path], stderr=subprocess.DEVNULL)
        strings = output.decode(errors="ignore").lower()
        for p in COMMON_PACKERS:
            if p in strings:
                detected.append(p)
        
        # Verifica se é UPX via magic header
        with open(path, "rb") as f:
            data = f.read(512)
            if b'UPX' in data:
                detected.append("upx-header")

    except Exception as e:
        log.warning(f"Erro na detecção de packers: {e}")

    return list(set(detected))
