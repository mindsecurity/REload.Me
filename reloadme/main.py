from __future__ import annotations

import os
import sys
import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich import print as rprint

from reloadme.analysis.static_analyzer import StaticAnalyzer
from reloadme.presentation.display import DisplayManager
from reloadme.mentorship.ai_mentor import AIMentor


app = typer.Typer(name="reloadme", help="ReloadMe - Static-first reverse engineering assistant")
console = Console()


def _timestamp() -> str:
    return datetime.datetime.now().strftime("[%H:%M:%S]")


def _check_file_readable(filepath: Path) -> bool:
    return filepath.is_file() and os.access(filepath, os.R_OK)


@app.command("analyse")
def analyse(filepath: str = typer.Argument(..., help="Caminho para o binário a analisar")):
    path = Path(filepath)

    if not _check_file_readable(path):
        rprint("[bold red]Erro: Arquivo não encontrado ou sem permissão de leitura.[/bold red]")
        raise typer.Exit(code=1)

    console.print(f"{_timestamp()} Analisando {filepath}...")

    with console.status("Executando análise estática inicial...", spinner="dots"):
        analyzer = StaticAnalyzer(str(path), r2_available=True)
        analysis_data = analyzer.run_full_analysis()
        # Enrich with detailed iI info
        try:
            analysis_data["bin_info"] = analyzer.analyze_bin_info()
        except Exception:
            analysis_data.setdefault("errors", []).append("Falha ao coletar informações detalhadas (iI).")
        # Best-effort decompilation of main via r2ghidra/pdc/pdr
        try:
            analysis_data.setdefault("decompilation", {})
            dmain = analyzer.decompile_main()
            if dmain:
                analysis_data["decompilation"]["main"] = dmain
        except Exception:
            pass

    display = DisplayManager(console)
    # Show detailed bin info and security features; omit high-level summary table
    display.display_bin_info(analysis_data)
    display.display_security(analysis_data)
    display.display_key_functions(analysis_data)
    display.display_all_functions(analysis_data)
    display.display_strings(analysis_data)
    display.display_pseudocode_main(analysis_data)
    display.display_errors(analysis_data)

    # AI mentor (optional): read API key from env or .r2ai.openai-key
    api_key = os.getenv("OPENAI_API_KEY")
    mentor = AIMentor(analysis_data=analysis_data, api_key=api_key)
    insights = mentor.get_mentorship()
    if insights:
        display.display_mentor_insights(insights)
    else:
        rprint("[bold yellow]Aviso: Não foi possível contatar o Mentor de IA. Exibindo apenas a análise estática local.[/bold yellow]")


# Alias com grafia americana
@app.command("analyze")
def analyze(filepath: str = typer.Argument(..., help="Path to the binary to analyze")):
    return analyse(filepath)


def main():
    app()


if __name__ == "__main__":
    main()
