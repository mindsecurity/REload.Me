#!/usr/bin/env python3
# REloadAI – Análise de binários com IA
# Atualizado: 2025-05-01

import os
import sys
import argparse
import r2pipe
import resource
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box
from openai import OpenAI

from src.common.sanitizer import BinarySanitizer
from src.common.interpreter import get_interp

console = Console()

# ───────────────────────────── CLI ──────────────────────────────
parser = argparse.ArgumentParser(
    description="REloadAI – Engenharia Reversa com Inteligência Artificial"
)
parser.add_argument("-f", "--file", required=True, help="Caminho do binário a ser analisado")
parser.add_argument(
    "-d",
    "--deep",
    action="store_true",
    help="Forçar última etapa (aaa) mesmo que consuma muita RAM/CPU",
)
args = parser.parse_args()

# ───────── Limite de memória (soft) p/ evitar OOM-killer ─────────
# 4 GB (ajuste se precisar); 0 = ilimitado
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024 ** 3, hard))
except Exception:
    pass  # nem todo SO permite, mas tentamos

# ─────────────────────── Carrega chave OpenAI ───────────────────
api_key_path = os.path.expanduser("~/.r2ai.openai-key")
if not os.path.exists(api_key_path):
    console.print("[red]Chave OpenAI não encontrada: ~/.r2ai.openai-key[/red]")
    sys.exit(1)

with open(api_key_path, "r") as f:
    api_key = f.read().strip()

model_name = os.getenv("OPENAI_MODEL", "gpt-4o")
client = OpenAI(api_key=api_key)

# ───────────────────── Sanitização inicial 🔐 ───────────────────
try:
    meta = BinarySanitizer.sanitize(args.file)
    console.print(
        Panel(
            f"[bold]Arquivo:[/bold] {meta['name']}\n"
            f"[bold]SHA-256:[/bold] {meta['sha256']}\n"
            f"[bold]Tamanho:[/bold] {meta['size']/1024:.1f} KB\n"
            f"[bold]MIME:[/bold] {meta['mime']}",
            title="Sanitização OK",
            border_style="green",
        )
    )
    file_path = meta["path"]
except Exception as e:
    console.print(f"[red]Erro na sanitização: {e}[/red]")
    sys.exit(1)

# ───────────────────── Verifica interpreter ───────────────────
interp = get_interp(file_path)
if interp:
    exists = os.path.exists(
        interp if os.path.isabs(interp)
        else os.path.join(os.path.dirname(file_path), interp.lstrip("./"))
    )
    console.print(
        Panel(
            f"{interp}   "
            + ("[green]✔ encontrado[/green]" if exists else "[red]✖ não encontrado[/red]"),
            title="Loader",
            border_style="yellow",
        )
    )
    if not exists:
        console.print(
            "[yellow]⚠ Execução dinâmica exigirá rodar o binário no diretório original "
            "ou montar ./glibc/ dentro do contêiner.[/yellow]"
        )

# ─────────────── Abre binário no radare2 com camadas ────────────
try:
    r2 = r2pipe.open(file_path, flags=["-2"])  # -2 desliga análise auto
except Exception as e:
    console.print(f"[red]Falha ao abrir binário no radare2: {e}[/red]")
    sys.exit(1)


def safe_cmd(r2obj, cmd: str, desc: str = "", timeout: int = 30):
    """Executa comando radare2 com timeout e captura falhas/OOM."""
    try:
        r2obj.cmd(f"e anal.timeout={timeout}")
        return r2obj.cmd(cmd)
    except RuntimeError as err:
        console.print(f"[yellow]{desc or cmd} falhou: {err}[/yellow]")
        return None


# ──────────────── CAMADA 1 – análise leve (aa) ──────────────────
console.status("[bold green]Inicializando análise rápida…")
safe_cmd(r2, "aa", "aa (análise leve)", timeout=20)
functions = r2.cmdj("aflj") or []

# ─────────── CAMADA 2 – incremental a partir do entrypoint ──────
if not functions:
    console.print(
        "[yellow]Nenhuma função após 'aa'. "
        "Fazendo varredura incremental (BFS) a partir do entrypoint…[/yellow]"
    )
    entry = r2.cmdj("iej")[0]["vaddr"]
    queue, seen = [entry], set()
    while queue:
        addr = queue.pop(0)
        if addr in seen:
            continue
        seen.add(addr)
        safe_cmd(r2, f"af @ {addr}", f"af @{hex(addr)}", timeout=10)
        for callee in r2.cmdj(f"agCj @ {addr}") or []:
            queue.append(callee.get("addr", 0))
    functions = r2.cmdj("aflj") or []

# ─────────── CAMADA 3 – profunda opcional (aaa) ─────────────────
if not functions and args.deep:
    console.print("[yellow]Última tentativa: 'aaa' com limites[/yellow]")
    safe_cmd(r2, "e anal.depth=4")
    safe_cmd(r2, "aaa", "aaa profunda", timeout=60)
    functions = r2.cmdj("aflj") or []

if not functions:
    console.print("[red]Nenhuma função identificada após todas as tentativas. Abortando.[/red]")
    r2.quit()
    sys.exit(1)

# ────────────────────── Reconhecimento rápido ───────────────────
console.rule("[bold blue]🔎 Detalhes do binário")
bin_info = r2.cmd("iI")
console.print(Panel(bin_info, title="[cyan]Info do binário (iI)", box=box.ROUNDED))
if "ELF" in bin_info:
    console.print("[green]Formato detectado: ELF (Linux).")
elif "PE" in bin_info:
    console.print("[green]Formato detectado: PE (Windows).")
else:
    console.print("[yellow]Formato não claramente identificado (ELF/PE).")

# ───────────────────── Proteções (checksec) ─────────────────────
console.rule("[bold blue]🛡️ Proteções Ativas")
checksec = r2.cmd("i~canary,relro,nx,pie,fortify")
console.print(Panel(checksec, title="[cyan]Resultado do checksec", box=box.ROUNDED))
prompt_protecao = (
    "Explique quais proteções estão ativas, o que cada uma faz e como burlá-las:\n"
    + checksec
)
res_protecao = client.chat.completions.create(
    model=model_name,
    messages=[
        {
            "role": "system",
            "content": (
                "Explique como um professor de segurança ofensiva para iniciantes, "
                "de forma detalhada e acessível."
            ),
        },
        {"role": "user", "content": prompt_protecao},
    ],
)
console.print(Markdown(res_protecao.choices[0].message.content))

# ─────────────────────── Strings interessantes ──────────────────
console.rule("[bold green]🧵 Strings Interessantes")
strings_raw = r2.cmd("izz")
interesting = [
    s
    for s in strings_raw.splitlines()
    if any(x in s.lower() for x in ("flag", "senha", "key", "secret", "input"))
]
preview = "\n".join(interesting[:300])
console.print(
    Panel(
        preview or "Nenhuma string suspeita encontrada.",
        title="[magenta]Strings úteis",
        box=box.ROUNDED,
    )
)

# ─────────────────── Análise de funções (estática) ──────────────
console.rule("[bold yellow]🧠 Analisando Funções Suspeitas")
report_md, report_aula = [], []

main_func = next((f for f in functions if f.get("name", "").endswith("main")), None)
if not main_func:
    console.print("[yellow]Função main não encontrada – continuando com a primeira função.[/yellow]")
    main_func = functions[0]

addr = main_func.get("offset") or main_func.get("addr")
r2.cmd(f"s {addr}")
disasm = safe_cmd(r2, "pdf", "pdf main", timeout=20) or ""
console.rule(f"[bold bright_white]🔍 {main_func['name']} @ {hex(addr)}")

# Exploit rand()
if "call sym.rand" in disasm or "call sym.imp.rand" in disasm:
    console.print("[yellow]Chamada rand() detectada. Gerando exploit em C via GPT…")
    prompt_exploit = (
        "Você é especialista em engenharia reversa de CTF.\n"
        "Gere um exploit C mínimo para reproduzir a lógica envolvendo rand():\n\n"
        + disasm
    )
    try:
        exploit_resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "Gere exploit C mínimo e bem comentado."},
                {"role": "user", "content": prompt_exploit},
            ],
        )
        exploit_code = exploit_resp.choices[0].message.content.strip()
        console.rule("[bold magenta]Exploit Gerado")
        console.print(Panel(Markdown(exploit_code), title="Código C", box=box.ROUNDED))
        with open("exploit.c", "w") as f:
            f.write(exploit_code + "\n")
        console.print("[green]Exploit salvo em exploit.c[/green]")
    except Exception as ee:
        console.print(f"[red]Falha ao gerar exploit: {ee}[/red]")

# Explicação detalhada
prompt_func = (
    "Explique detalhadamente a função abaixo, identifique vulnerabilidades e "
    "faça explicação didática para iniciantes:\n\n" + disasm
)
try:
    resp = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "Você é expert em engenharia reversa."},
            {"role": "user", "content": prompt_func},
        ],
    )
    answer = resp.choices[0].message.content.strip()
    console.print(Panel(Markdown(answer), title="[green]Análise da função", box=box.ROUNDED))
except Exception as e:
    console.print(f"[red]Erro na consulta GPT: {e}[/red]")

# ─────────────────────────── Fim ────────────────────────────────
r2.quit()
console.rule("[bold green]✅ Análise finalizada com sucesso")
