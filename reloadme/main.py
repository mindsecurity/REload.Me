from __future__ import annotations

import os
import sys
import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich import print as rprint

from reloadme.analysis.static_analyzer import StaticAnalyzer
from reloadme.analysis.cfg_analyzer import CFGAnalyzer
from reloadme.presentation.display import DisplayManager
from reloadme.presentation.cfg_display import CFGDisplay
from reloadme.mentorship.ai_mentor import AIMentor


app = typer.Typer(name="reloadme", help="ReloadMe - Static-first reverse engineering assistant")
console = Console()


def _timestamp() -> str:
    return datetime.datetime.now().strftime("[%H:%M:%S]")


def _check_file_readable(filepath: Path) -> bool:
    return filepath.is_file() and os.access(filepath, os.R_OK)


@app.command("analyse")
def analyse(
    filepath: str = typer.Argument(..., help="Caminho para o binário a analisar"),
    cfg: bool = typer.Option(False, "--cfg", help="Incluir análise de Control Flow Graph (CFG)"),
    cfg_function: str = typer.Option(None, "--cfg-function", help="Analisar CFG de função específica"),
):
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

    # CFG Analysis (se solicitada)
    if cfg or cfg_function:
        console.print()
        console.rule("[bold cyan]Control Flow Graph Analysis[/bold cyan]")
        console.print()
        
        with console.status("Gerando Control Flow Graph...", spinner="dots"):
            cfg_analyzer = CFGAnalyzer(str(path))
            
            # Verificar se angr está disponível
            if not cfg_analyzer.angr_available:
                rprint("[bold red]❌ CFG Analysis Error:[/bold red] angr não está instalado")
                rprint("[bold yellow]💡 Instale com:[/bold yellow] pip install angr")
            else:
                try:
                    # Gerar CFG
                    if cfg_function:
                        cfg_data = cfg_analyzer.generate_cfg(function_name=cfg_function)
                    else:
                        cfg_data = cfg_analyzer.generate_cfg()
                    
                    # Exibir CFG no terminal
                    cfg_display = CFGDisplay(console)
                    cfg_display.display_full_cfg_analysis(cfg_data, show_details=True)
                    
                except Exception as e:
                    rprint(f"[bold red]❌ CFG Analysis Error:[/bold red] {str(e)}")

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
def analyze(
    filepath: str = typer.Argument(..., help="Path to the binary to analyze"),
    cfg: bool = typer.Option(False, "--cfg", help="Include Control Flow Graph (CFG) analysis"),
    cfg_function: str = typer.Option(None, "--cfg-function", help="Analyze CFG for specific function"),
):
    return analyse(filepath, cfg, cfg_function)


def main():
    app()


if __name__ == "__main__":
    main()
