from __future__ import annotations

from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.syntax import Syntax


class DisplayManager:
    def __init__(self, console: Console):
        self.console = console

    def display_security(self, data: Dict[str, Any]):
        security = data.get("security", {}) or {}
        if not security:
            return
        sec_table = Table(title="Features de Segurança", expand=True)
        sec_table.add_column("Recurso")
        sec_table.add_column("Status")
        def fmt_status(val):
            if isinstance(val, bool):
                return "Enabled" if val else "Disabled"
            if val is None:
                return "Unknown"
            return str(val)
        features = [
            ("canary", "Canary"),
            ("nx", "NX (DEP)"),
            ("pie", "PIE"),
            ("aslr", "ASLR"),
            ("relro", "RELRO"),
            ("fortify", "Fortify"),
        ]
        for key, label in features:
            sec_table.add_row(label, fmt_status(security.get(key)))
        self.console.print(sec_table)

    def display_errors(self, data: Dict[str, Any]):
        errors: List[str] = data.get("errors", []) or []
        if not errors:
            return
        err_panel = Panel("\n".join(f"• {e}" for e in errors), title="Avisos/Erros", title_align="left", style="bold yellow")
        self.console.print(err_panel)

    def display_bin_info(self, data: Dict[str, Any]):
        info = data.get("bin_info") or {}
        if not isinstance(info, dict) or not info:
            return
        table = Table(title="Informações do Binário (iI)", expand=True)
        table.add_column("Campo", style="bold")
        table.add_column("Valor")
        # Curated keys commonly present in iI
        keys = [
            ("bintype", "BinType"),
            ("class", "Class"),
            ("machine", "Machine"),
            ("bits", "Bits"),
            ("endian", "Endian"),
            ("os", "OS"),
            ("subsys", "Subsystem"),
            ("static", "Static"),
            ("stripped", "Stripped"),
            ("pic", "PIC"),
            ("relro", "RELRO"),
            ("rpath", "RPath"),
            ("runpath", "RunPath"),
            ("intrp", "Interpreter"),
        ]
        for k, label in keys:
            if k in info and info.get(k) not in (None, ""):
                table.add_row(label, str(info.get(k)))
        self.console.print(table)

    # Imports table intentionally removed per user request.

    def display_key_functions(self, data: Dict[str, Any]):
        funcs = data.get("key_functions", []) or []
        if not funcs:
            return
        table = Table(title="Funções Principais", expand=True)
        table.add_column("Endereço")
        table.add_column("Nome da Função")
        table.add_column("Nota")
        for f in funcs:
            addr_va = f.get("address_va") or f.get("address") or ""
            addr_pa = f.get("address_pa")
            addr = str(addr_va)
            if addr_pa:
                addr = f"{addr} (PA {addr_pa})"
            name = str(f.get("name", ""))
            note = "Entrada" if f.get("is_entrypoint") else ""
            table.add_row(addr, name, note)
        self.console.print(table)

    def display_all_functions(self, data: Dict[str, Any]):
        funcs = data.get("functions", []) or []
        if not funcs:
            return
        table = Table(title="Todas as Funções (aflj)", expand=True, show_lines=False)
        table.add_column("Endereço", no_wrap=True)
        table.add_column("Size", justify="right")
        table.add_column("RealSz", justify="right")
        table.add_column("BBs", justify="right")
        table.add_column("CallType", justify="left")
        table.add_column("Args", justify="right")
        table.add_column("Nome")
        for f in funcs:
            addr = str(f.get("address", ""))
            size = str(f.get("size", ""))
            realsz = str(f.get("realsz", ""))
            nbbs = str(f.get("nbbs", ""))
            calltype = str(f.get("calltype", ""))
            nargs = str(f.get("nargs", ""))
            name = str(f.get("name", ""))
            table.add_row(addr, size, realsz, nbbs, calltype, nargs, name)
        self.console.print(table)

    def display_strings(self, data: Dict[str, Any]):
        strings = data.get("strings", []) or []
        if not strings:
            return
        # Show first N strings in a compact panel
        snippet = "\n".join(strings[:50])
        self.console.print(Panel(snippet, title="Strings (top 50)", expand=True))

    def display_mentor_insights(self, insights_text: str):
        md = Markdown(insights_text)
        panel = Panel(md, title="Análise e Recomendações do Mentor de IA", expand=True)
        self.console.print(panel)

    def display_pseudocode_main(self, data: Dict[str, Any]):
        decomp = (data.get("decompilation") or {}).get("main")
        if not isinstance(decomp, dict):
            return
        code = decomp.get("code")
        if not code:
            return
        title = f"Pseudocódigo C - {decomp.get('name','main')} ({decomp.get('engine','decompiler')})"
        try:
            syn = Syntax(code, "c", word_wrap=False)
            self.console.print(Panel(syn, title=title, expand=True))
        except Exception:
            self.console.print(Panel(code, title=title, expand=True))
