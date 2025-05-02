#!/usr/bin/env python3
"""
REloadAI CLI – ponto de entrada clássico para análise de binários.
"""

import os
import sys
import argparse
import resource

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from openai import OpenAI

from utils.sanitizer import BinarySanitizer
from utils.interpreter import get_interp
from core.fingerprints import ssdeep_hash, imphash, tlsh_hash, capa_features
from core.packers import detect_packer
from core.analyzer import BinaryAnalyzer
from core.dynamic import DynamicAnalyzer
from core.exploit_gen import ExploitGenerator
from core.bof_solver import BOFSolver
from core.cfg_visualizer import CFGVisualizer

console = Console()


def _limit_memory(max_bytes: int):
    """Limita o AS (address space) para evitar OOM-killer."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        resource.setrlimit(resource.RLIMIT_AS, (max_bytes, hard))
    except Exception:
        pass  # pode falhar em alguns SOs


def main():
    parser = argparse.ArgumentParser(
        description="REloadAI – Engenharia Reversa com Inteligência Artificial"
    )
    parser.add_argument(
        "file", help="Caminho para o binário a ser analisado"
    )
    parser.add_argument(
        "-d", "--deep", action="store_true",
        help="Forçar análise profunda (aaa), consumindo mais recursos"
    )
    parser.add_argument(
        "--dynamic", action="store_true",
        help="Executar também análise dinâmica (docker/unicorn/frida)"
    )
    parser.add_argument(
        "--sandbox", choices=["docker", "unicorn", "frida"],
        default="docker", help="Tipo de sandbox para análise dinâmica"
    )
    parser.add_argument(
        "--bof", action="store_true",
        help="Tentar pipeline automático de Buffer Overflow (32/64-bit)"
    )
    parser.add_argument(
        "--cfg", metavar="FUNC", nargs="?", const="main",
        help="Gerar visualização 3D do CFG (padrão: main)"
    )
    args = parser.parse_args()

    console.rule("[bold green]🚀 Iniciando REloadAI CLI")

    # 1) Limitar memória a 4 GB por segurança
    _limit_memory(4 * 1024**3)

    # 2) Carregar chave OpenAI
    key_path = os.path.expanduser("~/.r2ai.openai-key")
    if not os.path.isfile(key_path):
        console.print("[red]Chave OpenAI não encontrada em ~/.r2ai.openai-key[/red]")
        sys.exit(1)
    with open(key_path) as f:
        api_key = f.read().strip()
    client = OpenAI(api_key=api_key)

    # 3) Sanitização e metadados
    try:
        meta = BinarySanitizer.sanitize(args.file)
    except Exception as e:
        console.print(f"[red]Erro na sanitização: {e}[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold]Arquivo:[/bold] {meta['name']}\n"
            f"[bold]SHA256:[/bold] {meta['sha256']}\n"
            f"[bold]Tamanho:[/bold] {meta['size'] / 1024:.1f} KB\n"
            f"[bold]MIME:[/bold] {meta['mime']}",
            title="🔐 Sanitização OK",
            border_style="green"
        )
    )
    path = meta["path"]

    # 4) Fingerprints & Packer detection
    fp_ssdeep = ssdeep_hash(path) or "n/a"
    fp_imph   = imphash(path)   or "n/a"
    fp_tlsh   = tlsh_hash(path) or "n/a"
    fp_capa   = capa_features(path) or "n/a"
    packer    = detect_packer(path) or "none"

    console.print(
        Panel(
            f"ssdeep: {fp_ssdeep}\n"
            f"imphash: {fp_imph}\n"
            f"tlsh: {fp_tlsh}\ncapa: {fp_capa}",
            title="🔖 Fingerprints",
            border_style="cyan"
        )
    )
    console.print(f"[cyan]Packer detectado:[/cyan] {packer}")

    # 5) Análise estática
    analyzer = BinaryAnalyzer(path, deep=args.deep)
    results = analyzer.run_full_analysis()

    console.rule("[bold blue]🛠️ Análise Estática Concluída")
    console.print(Markdown(results.get("summary_md", "")))

    # 6) Análise dinâmica (opcional)
    if args.dynamic:
        dyn = DynamicAnalyzer(path, sandbox=args.sandbox)
        dyn_res = dyn.analyze()
        console.rule("[bold blue]🐳 Análise Dinâmica Concluída")
        console.print(Markdown(dyn_res.get("summary_md", "")))

    # 7) Auto-BoF solver (opcional)
    if args.bof:
        bof = BOFSolver(path)
        bof_res = bof.solve()
        console.rule("[bold blue]💥 BOF Solver Concluído")
        console.print(Markdown(bof_res.get("report_md", "")))

    # 8) CFG 3D (opcional)
    if args.cfg:
        viz = CFGVisualizer(path)
        html = viz.export_cfg(args.cfg, format="html")
        out = f"cfg_{args.cfg}.html"
        with open(out, "w") as f:
            f.write(html)
        console.print(f"[green]CFG 3D salvo em {out}[/green]")

    console.rule("[bold green]✅ REloadAI CLI finalizado")
