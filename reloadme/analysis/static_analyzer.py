from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _read_magic(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        return f.read(4)


def _is_pe(filepath: str) -> bool:
    magic = _read_magic(filepath)
    return magic[:2] == b"MZ"


def _is_elf(filepath: str) -> bool:
    magic = _read_magic(filepath)
    return magic == b"\x7fELF"


@dataclass
class StaticAnalyzer:
    filepath: str
    r2_available: bool = True
    analysis_data: Dict[str, Any] = field(default_factory=dict)

    def run_full_analysis(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "filepath": self.filepath,
            "file_type": self.get_file_type(),
            "headers": {},
            "imports": [],
            "functions": [],
            "key_functions": [],
            "strings": [],
            "security": {},
            "decompilation": {},
            "errors": [],
        }

        try:
            headers = self.analyze_headers()
            data["headers"] = headers or {}
        except Exception:
            data["errors"].append("Falha ao analisar os cabeÃ§alhos do binÃ¡rio.")

        try:
            imports = self.analyze_imports()
            data["imports"] = imports or []
        except Exception:
            data["errors"].append("Falha ao analisar as importaÃ§Ãµes do binÃ¡rio.")

        try:
            key_funcs = self.find_key_functions()
            data["key_functions"] = key_funcs or []
        except Exception:
            data["errors"].append("Falha ao identificar funÃ§Ãµes principais.")

        # Full function list (aflj)
        try:
            all_funcs = self.list_all_functions()
            data["functions"] = all_funcs or []
        except Exception:
            data["errors"].append("Falha ao listar todas as fun����es.")

        try:
            strings = self.extract_strings()
            data["strings"] = strings or []
        except Exception:
            data["errors"].append("Falha ao extrair strings.")

        try:
            sec = self.check_security_features()
            data["security"] = sec or {}
        except Exception:
            data["errors"].append("Falha ao verificar features de seguranÃ§a.")

        self.analysis_data = data
        return data

    # ---- r2 helpers ----
    def _open_r2(self, analyze: bool = True, va: bool = True):
        import r2pipe  # type: ignore
        flags = ["-2"]
        r2 = r2pipe.open(self.filepath, flags=flags)
        # Switch to virtual addressing if requested
        if va:
            try:
                r2.cmd("e io.va = true")
            except Exception:
                pass
        # Perform analysis pass explicitly (preferred in r2pipe flows)
        if analyze:
            try:
                r2.cmd("aaa")
            except Exception:
                pass
        return r2

    def get_file_type(self) -> str:
        try:
            if _is_pe(self.filepath):
                return "PE"
            if _is_elf(self.filepath):
                return "ELF"
        except Exception:
            # Ignore detection errors; fall through to UNKNOWN
            pass
        return "UNKNOWN"

    def analyze_headers(self) -> Dict[str, Any]:
        ftype = self.get_file_type()
        if ftype == "PE":
            return self._analyze_headers_pe()
        elif ftype == "ELF":
            return self._analyze_headers_elf()
        else:
            return {}

    def analyze_imports(self) -> List[Dict[str, Any]]:
        ftype = self.get_file_type()
        # Prefer r2pipe iij for a complete, uniform view across formats
        if self.r2_available:
            via_r2 = self._analyze_imports_r2()
            if via_r2:
                return via_r2
        if ftype == "PE":
            return self._analyze_imports_pe()
        elif ftype == "ELF":
            return self._analyze_imports_elf()
        else:
            return []

    def find_key_functions(self) -> List[Dict[str, Any]]:
        # Use r2pipe if available to list functions and find entrypoints
        if not self.r2_available:
            return []
        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                funcs_json = r2.cmd("aflj")
                funcs = json.loads(funcs_json) if funcs_json else []
                info_json = r2.cmd("ij")
                info = json.loads(info_json) if info_json else {}
                entry_json = r2.cmd("iej")
                entries = json.loads(entry_json) if entry_json else []
                exports_json = r2.cmd("iEj")
                exports = json.loads(exports_json) if exports_json else []
            finally:
                r2.quit()

            def _to_int_addr(x: Any) -> Optional[int]:
                try:
                    if isinstance(x, int):
                        return x
                    if isinstance(x, str):
                        s = x.strip().lower()
                        if s.startswith("0x"):
                            return int(s, 16)
                        if s.isdigit():
                            return int(s)
                except Exception:
                    return None
                return None

            def _fmt_addr(x: Any) -> str:
                xi = _to_int_addr(x)
                if isinstance(xi, int) and xi >= 0:
                    return f"0x{xi:x}"
                return str(x)

            def _get_addr_from_func(f: Dict[str, Any]) -> Optional[int]:
                for k in ("offset", "addr", "vaddr", "plt", "paddr"):
                    if k in f:
                        ai = _to_int_addr(f.get(k))
                        if isinstance(ai, int) and ai >= 0:
                            return ai
                return None

            key_exact = {"main", "sym.main", "entry0", "_start", "WinMain", "wWinMain", "mainCRTStartup"}
            result: List[Dict[str, Any]] = []
            seen_offsets = set()

            # Prioritize real entry from iej (preferred), then bin.entry
            entry_off = None
            entry_pa = None
            if isinstance(entries, list) and entries:
                eo = entries[0]
                if isinstance(eo, dict):
                    entry_off = _to_int_addr(eo.get("vaddr") or eo.get("addr") or eo.get("paddr"))
                    entry_pa = _to_int_addr(eo.get("paddr"))
            if entry_off is None:
                bininfo = (info or {}).get("bin", {}) if isinstance(info, dict) else {}
                if isinstance(bininfo, dict):
                    entry_off = _to_int_addr(bininfo.get("entry"))
            if isinstance(entry_off, int) and entry_off is not None and entry_off >= 0:
                match = None
                for f in funcs or []:
                    off = _get_addr_from_func(f) or -1
                    if off == entry_off:
                        match = f
                        break
                name = (match or {}).get("name", "entry0")
                result.append({
                    "name": name,
                    "address": _fmt_addr(entry_off),
                    "address_va": _fmt_addr(entry_off),
                    "address_pa": _fmt_addr(entry_pa) if isinstance(entry_pa, int) and entry_pa >= 0 else None,
                    "size": (match or {}).get("size"),
                    "is_entrypoint": True,
                })
                seen_offsets.add(entry_off)

            # Then add common key names
            for f in funcs or []:
                off = _get_addr_from_func(f) or 0
                if off in seen_offsets:
                    continue
                name = f.get("name", "")
                low = name.lower()
                if name in key_exact or any(k in low for k in ["main", "entry0", "_start", "winmain", "wWinMain".lower()]):
                    result.append({
                        "name": name,
                        "address": _fmt_addr(off),
                        "address_va": _fmt_addr(off),
                        "address_pa": None,
                        "size": f.get("size"),
                        "is_entrypoint": name in {"entry0", "_start"},
                    })
                    seen_offsets.add(off)

            # Also consider exports that look like main or entry
            for e in exports or []:
                if not isinstance(e, dict):
                    continue
                name = str(e.get("name", ""))
                low = name.lower()
                if not (name in key_exact or any(k in low for k in ["main", "entry0", "_start", "winmain"])):
                    continue
                vaddr = _to_int_addr(e.get("vaddr") or e.get("plt") or e.get("addr"))
                if isinstance(vaddr, int) and vaddr not in seen_offsets:
                    result.append({
                        "name": name,
                        "address": _fmt_addr(vaddr),
                        "address_va": _fmt_addr(vaddr),
                        "address_pa": _fmt_addr(_to_int_addr(e.get("paddr"))) if isinstance(_to_int_addr(e.get("paddr")), int) else None,
                        "size": None,
                        "is_entrypoint": False,
                    })
                    seen_offsets.add(vaddr)

            # Add a few nearest-by functions around entrypoint for context
            extra_added = 0
            if isinstance(entry_off, int):
                try:
                    sorted_by_distance = sorted(
                        (funcs or []), key=lambda f: abs(((_get_addr_from_func(f) or 0)) - entry_off)
                    )
                    for f in sorted_by_distance:
                        if extra_added >= 5:
                            break
                        off = _get_addr_from_func(f) or 0
                        if off in seen_offsets:
                            continue
                        result.append({
                            "name": f.get("name", ""),
                            "address": _fmt_addr(off),
                            "address_va": _fmt_addr(off),
                            "address_pa": None,
                            "size": f.get("size"),
                            "is_entrypoint": False,
                        })
                        seen_offsets.add(off)
                        extra_added += 1
                except Exception:
                    pass
            # If still empty, include first few as last resort
            if not result:
                for f in (funcs or [])[:5]:
                    off = _get_addr_from_func(f) or 0
                    if off in seen_offsets:
                        continue
                    result.append({
                        "name": f.get("name", ""),
                        "address": _fmt_addr(off),
                        "address_va": _fmt_addr(off),
                        "address_pa": None,
                        "size": f.get("size"),
                        "is_entrypoint": False,
                    })
                    seen_offsets.add(off)
            return result
        except Exception:
            return []

    def list_all_functions(self) -> List[Dict[str, Any]]:
        if not self.r2_available:
            return []
        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                funcs_json = r2.cmd("aflj")
                funcs = json.loads(funcs_json) if funcs_json else []
            finally:
                r2.quit()

            def _to_int_addr(x: Any) -> Optional[int]:
                try:
                    if isinstance(x, int):
                        return x
                    if isinstance(x, str):
                        s = x.strip().lower()
                        if s.startswith("0x"):
                            return int(s, 16)
                        if s.isdigit():
                            return int(s)
                except Exception:
                    return None
                return None

            def _fmt_addr(x: Any) -> str:
                xi = _to_int_addr(x)
                if isinstance(xi, int) and xi >= 0:
                    return f"0x{xi:x}"
                return str(x)

            def _get_addr_from_func(f: Dict[str, Any]) -> Optional[int]:
                for k in ("offset", "addr", "vaddr", "plt", "paddr"):
                    if k in f:
                        ai = _to_int_addr(f.get(k))
                        if isinstance(ai, int) and ai >= 0:
                            return ai
                return None

            out: List[Dict[str, Any]] = []
            for f in funcs or []:
                calltype = f.get("calltype") or f.get("cc")
                off = _get_addr_from_func(f)
                out.append({
                    "name": f.get("name", ""),
                    "address": _fmt_addr(off) if off is not None else "",
                    "size": f.get("size"),
                    "realsz": f.get("realsz"),
                    "nbbs": f.get("nbbs"),
                    "calltype": calltype,
                    "nargs": f.get("nargs"),
                    "noreturn": f.get("noreturn"),
                })
            return out
        except Exception:
            return []

    def decompile_main(self) -> Optional[Dict[str, Any]]:
        if not self.r2_available:
            return None
        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                # get functions list
                try:
                    funcs = r2.cmdj("aflj")  # type: ignore[attr-defined]
                except Exception:
                    fjson = r2.cmd("aflj")
                    funcs = json.loads(fjson) if fjson else []

                def _to_int_addr(x: Any) -> Optional[int]:
                    try:
                        if isinstance(x, int):
                            return x
                        if isinstance(x, str):
                            s = x.strip().lower()
                            if s.startswith("0x"):
                                return int(s, 16)
                            if s.isdigit():
                                return int(s)
                    except Exception:
                        return None
                    return None

                def _get_addr_from_func(f: Dict[str, Any]) -> Optional[int]:
                    for k in ("offset", "addr", "vaddr", "plt", "paddr"):
                        if k in f:
                            ai = _to_int_addr(f.get(k))
                            if isinstance(ai, int) and ai >= 0:
                                return ai
                    return None

                target = None
                for f in funcs or []:
                    name = str(f.get("name", ""))
                    if name in {"main", "sym.main", "WinMain", "wWinMain"} or "main" in name.lower():
                        target = f
                        break
                if not target:
                    return None
                off = _get_addr_from_func(target)
                if not isinstance(off, int):
                    return None

                # Try r2ghidra JSON first
                code = None
                engine = None
                try:
                    pj = r2.cmdj(f"pdgj @{off}")  # type: ignore[attr-defined]
                    if isinstance(pj, dict):
                        code = pj.get("code") or pj.get("text")
                        engine = "r2ghidra(pdgj)"
                except Exception:
                    pass
                if not code:
                    try:
                        out = r2.cmd(f"pdg @{off}")
                        if out and out.strip():
                            code = out
                            engine = "r2ghidra(pdg)"
                    except Exception:
                        pass
                # Fallbacks
                if not code:
                    for cmd, eng in (("pdc", "pdc"), ("pdr", "pdr"), ("pdd", "pdd")):
                        try:
                            out = r2.cmd(f"{cmd} @{off}")
                            if out and out.strip():
                                code = out
                                engine = eng
                                break
                        except Exception:
                            continue
                if not code:
                    return None
                return {
                    "name": str(target.get("name", "main")),
                    "address": f"0x{off:x}",
                    "engine": engine or "unknown",
                    "code": code,
                }
            finally:
                r2.quit()
        except Exception:
            return None

    def extract_strings(self) -> List[str]:
        if not self.r2_available:
            # Fallback: simple byte scan for ASCII strings length > 5
            try:
                with open(self.filepath, "rb") as f:
                    data = f.read()
                current = []
                strings: List[str] = []
                for b in data:
                    if 32 <= b <= 126:
                        current.append(chr(b))
                    else:
                        if len(current) > 5:
                            strings.append("".join(current))
                        current = []
                if len(current) > 5:
                    strings.append("".join(current))
                return strings[:1000]
            except Exception:
                return []

        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                strings_json = r2.cmd("izj")
                entries = json.loads(strings_json) if strings_json else []
            finally:
                r2.quit()
            candidates = [e.get("string", "") for e in entries or [] if isinstance(e, dict)]
            return [s for s in candidates if isinstance(s, str) and len(s) > 5][:1000]
        except Exception:
            return []

    def check_security_features(self) -> Dict[str, Any]:
        if not self.r2_available:
            return {}
        try:
            r2 = self._open_r2(analyze=False, va=True)
            try:
                info_json = r2.cmd("ij")
                info = json.loads(info_json) if info_json else {}
            finally:
                r2.quit()

            bininfo = (info or {}).get("bin", {})
            sec = (bininfo or {}).get("sec", {})
            out = {
                "canary": bool(sec.get("canary")) if isinstance(sec, dict) else None,
                "nx": bool(sec.get("nx")) if isinstance(sec, dict) else None,
                "pie": bool(sec.get("pie")) if isinstance(sec, dict) else None,
                "aslr": bool(sec.get("aslr")) if isinstance(sec, dict) else None,
            }
            if isinstance(sec, dict):
                if "relro" in sec:
                    out["relro"] = sec.get("relro")
                if "fortify" in sec:
                    out["fortify"] = sec.get("fortify")
            return out
        except Exception:
            return {}

    # --- Internal helpers per format ---
    def _analyze_headers_pe(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        try:
            import pefile  # type: ignore

            pe = pefile.PE(self.filepath, fast_load=True)
            try:
                machine = pe.FILE_HEADER.Machine
                arch = "64-bit" if machine in (0x8664,) else "32-bit"
                result["arch"] = f"PE {arch}"
                result["timestamp"] = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
                characteristics = getattr(pe.FILE_HEADER, "Characteristics", 0)
                result["characteristics"] = characteristics
                # Optional: determine type (DLL/EXE)
                is_dll = bool(characteristics & 0x2000)
                result["type"] = "DLL" if is_dll else "ExecutÃ¡vel"
            finally:
                try:
                    pe.close()
                except Exception:
                    pass
        except Exception:
            result["error"] = "Falha ao ler cabeÃ§alhos PE."

        # Enrich with r2 if available
        if self.r2_available:
            try:
                import r2pipe  # type: ignore

                r2 = r2pipe.open(self.filepath, flags=["-2"])  # best-effort
                try:
                    info_json = r2.cmd("ij")
                    info = json.loads(info_json) if info_json else {}
                finally:
                    r2.quit()
                bininfo = (info or {}).get("bin", {})
                if bininfo:
                    result["r2_bininfo"] = bininfo
            except Exception:
                pass

        return result

    def _analyze_headers_elf(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if not self.r2_available:
            result["error"] = "radare2/r2pipe nÃ£o disponÃ­vel para ELF."
            return result
        try:
            r2 = self._open_r2(analyze=False, va=True)
            try:
                info_json = r2.cmd("ij")
                info = json.loads(info_json) if info_json else {}
            finally:
                r2.quit()

            bininfo = (info or {}).get("bin", {})
            if bininfo:
                result.update(
                    {
                        "arch": f"ELF {bininfo.get('bits', '')}-bit".strip(),
                        "os": bininfo.get("os"),
                        "class": bininfo.get("class"),
                        "type": bininfo.get("type"),
                        "loader": bininfo.get("intrp") or bininfo.get("interpreter"),
                    }
                )
        except Exception:
            result["error"] = "Falha ao ler cabeÃ§alhos ELF via r2."
        return result

    def _analyze_imports_pe(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        try:
            import pefile  # type: ignore

            pe = pefile.PE(self.filepath, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
                    for imp in entry.imports:
                        fname = imp.name.decode(errors='ignore') if isinstance(imp.name, (bytes, bytearray)) else str(imp.name)
                        results.append({"library": dll, "function": fname})
        except Exception:
            return results
        finally:
            try:
                pe.close()
            except Exception:
                pass
        return results

    def _analyze_imports_elf(self) -> List[Dict[str, Any]]:
        if not self.r2_available:
            return []
        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                # Prefer cmdj for parsed JSON directly
                try:
                    imps = r2.cmdj("iij")  # type: ignore[attr-defined]
                except Exception:
                    imps_json = r2.cmd("iij")
                    imps = json.loads(imps_json) if imps_json else []
            finally:
                r2.quit()
            results: List[Dict[str, Any]] = []
            for e in imps or []:
                if not isinstance(e, dict):
                    continue
                lib = e.get("lib", "") or e.get("library", "")
                name = e.get("name", "")
                addr = e.get("plt") or e.get("vaddr") or e.get("addr")
                if lib or name:
                    item = {"library": lib, "function": name}
                    if isinstance(addr, int):
                        item["address"] = f"0x{addr:x}"
                    results.append(item)
            return results
        except Exception:
            return []

    def _analyze_imports_r2(self) -> List[Dict[str, Any]]:
        """Generic import listing using r2pipe iij for both ELF and PE.
        Returns list of {library, function, address?}.
        """
        if not self.r2_available:
            return []
        try:
            r2 = self._open_r2(analyze=True, va=True)
            try:
                try:
                    imps = r2.cmdj("iij")  # type: ignore[attr-defined]
                except Exception:
                    imps_json = r2.cmd("iij")
                    imps = json.loads(imps_json) if imps_json else []
            finally:
                r2.quit()
            results: List[Dict[str, Any]] = []
            for e in imps or []:
                if not isinstance(e, dict):
                    continue
                lib = e.get("lib", "") or e.get("library", "")
                name = e.get("name", "")
                addr = e.get("plt") or e.get("vaddr") or e.get("addr")
                if not (lib or name):
                    continue
                item = {"library": lib, "function": name}
                if isinstance(addr, int):
                    item["address"] = f"0x{addr:x}"
                results.append(item)
            # If libraries are missing for PE, merge with pefile results to fill library names
            if self.get_file_type() == "PE" and any(not r.get("library") for r in results):
                try:
                    pe_imps = self._analyze_imports_pe()
                    # Build a map from function name to library for quick fill
                    fmap = {}
                    for it in pe_imps:
                        fname = it.get("function")
                        libname = it.get("library")
                        if fname and libname:
                            fmap.setdefault(fname, libname)
                    for r in results:
                        if not r.get("library") and r.get("function") in fmap:
                            r["library"] = fmap[r["function"]]
                except Exception:
                    pass
            return results
        except Exception:
            return []

    def analyze_bin_info(self) -> Dict[str, Any]:
        if not self.r2_available:
            return {}
        try:
            r2 = self._open_r2(analyze=False, va=True)
            try:
                info_json = r2.cmd("iIj")
                info = json.loads(info_json) if info_json else {}
            finally:
                r2.quit()
            if isinstance(info, list):
                info = info[0] if info else {}
            return info if isinstance(info, dict) else {}
        except Exception:
            return {}

