import r2pipe
import re

def get_interp(path: str) -> str | None:
    """Retorna o caminho do interpreter (ld.so) ou None."""
    try:
        # uso ultrarrápido: iIj (json) sempre traz 'intrp'
        r2 = r2pipe.open(path, flags=["-2"])
        info = r2.cmdj("iIj")
        r2.quit()

        interp = info.get("intrp")            # radare2 ≥ 5.7
        if interp:
            return interp.strip()

        # fallback: parse saída textual de iI (qualquer versão)
        raw = r2pipe.open(path).cmd("iI")
        match = re.search(r"^\s*intrp\s+(.*)$", raw, re.MULTILINE)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None
