import r2pipe
from utils.logging import get_logger
from utils.constants import SAFE_TIMEOUT

log = get_logger(__name__)

SENSITIVE_CALLS = [
    "gets", "strcpy", "strncpy", "sprintf", "system", "scanf",
    "memcpy", "memcmp", "fgets", "strcmp", "rand", "malloc",
    "free", "ptrace", "mprotect"
]

def analyze_static(path: str, deep: bool = False) -> dict:
    r2 = r2pipe.open(path, flags=["-2"])
    r2.cmd(f"e anal.timeout={SAFE_TIMEOUT}")

    result = {
        "functions": [],
        "main_disasm": "",
        "main_addr": None,
        "arch": None,
        "bits": None,
        "rop_gadgets": [],
        "sensitive_calls": [],
        "cfg": "",
    }

    try:
        r2.cmd("aa")
        funcs = r2.cmdj("aflj") or []

        if not funcs and deep:
            r2.cmd("e anal.depth=4")
            r2.cmd("aaa")
            funcs = r2.cmdj("aflj") or []

        result["functions"] = funcs
        binmeta = r2.cmdj("ij")["bin"]
        result["arch"] = binmeta.get("arch")
        result["bits"] = binmeta.get("bits")

        main_func = next((f for f in funcs if f.get("name", "").endswith("main")), None)
        if not main_func and funcs:
            main_func = funcs[0]

        if main_func:
            addr = main_func.get("offset") or main_func.get("addr")
            result["main_addr"] = addr
            r2.cmd(f"s {addr}")
            disasm = r2.cmd("pdf")
            result["main_disasm"] = disasm

            # Detecta chamadas sensíveis na função main
            for call in SENSITIVE_CALLS:
                if call in disasm:
                    result["sensitive_calls"].append(call)

        # Extração de gadgets ROP curtos
        rop = r2.cmd("/Rj 3")
        if rop:
            try:
                import json
                rop_json = json.loads(rop)
                result["rop_gadgets"] = [g["opcode"] for g in rop_json if "opcode" in g]
            except Exception:
                pass

        # Exportação de grafo de chamadas como DOT
        result["cfg"] = r2.cmd("agCd")

    except Exception as e:
        log.error(f"Erro na análise estática: {e}")

    finally:
        r2.quit()

    return result
