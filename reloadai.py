import os, r2pipe, argparse
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box
from fpdf import FPDF
from openai import OpenAI

# Uso:
# python reloadai.py -f /path/to/binary

parser = argparse.ArgumentParser(description="REloadAI: Engenharia Reversa com IA")
parser.add_argument("-f", "--file", required=True, help="Caminho do binário a ser analisado")
args = parser.parse_args()

console = Console()

api_key_path = os.path.expanduser("~/.r2ai.openai-key")
with open(api_key_path, 'r') as f:
    api_key = f.read().strip()

client = OpenAI(api_key=api_key)

# Protecoes que queremos checar
protections = ["canary", "nx", "pie", "relro", "fortify"]
sensitive_calls = [
    "gets", "strcpy", "strncpy", "sprintf", "system", "scanf",
    "memcpy", "memcmp", "fgets", "strcmp", "rand", "malloc",
    "free", "ptrace", "mprotect"
]

# Abre o binário informado via parâmetro
r2 = r2pipe.open(args.file)
r2.cmd('aaa')

console.rule("[bold blue]🔎 Detalhes do binário")
bin_info = r2.cmd("iI")  # Informações detalhadas do binário
console.print(Panel(bin_info, title="[cyan]Info do binário (iI)", box=box.ROUNDED))

# Verificando formato do binário (heurística simples)
if "ELF" in bin_info:
    console.print("[green]Formato detectado: ELF (provavelmente Linux).")
elif "PE" in bin_info:
    console.print("[green]Formato detectado: PE (Windows).")
else:
    console.print("[yellow]Formato não claramente identificado como ELF ou PE.")

console.rule("[bold blue]🛡️ Protecoes Ativas (checksec)")
checksec = r2.cmd('i~canary,relro,nx,pie,fortify')
console.print(Panel(checksec, title="[cyan]Resultado do checksec", box=box.ROUNDED))

prompt_protecao = f"""Explique quais dessas protecoes estao ativas, o que cada uma faz, e quais vulnerabilidades podem continuar existindo nesse binario mesmo com essas protecoes, e as melhores formas de bypassar essas proteções baseado no contexto do binario:\n{checksec}"""
res_protecao = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "Explique como um professor especialista de segurança ofensiva para autistas iniciantes, com foco em engenharia reversa."},
        {"role": "user", "content": prompt_protecao}
    ]
)
console.print(Markdown(res_protecao.choices[0].message.content))

console.rule("[bold green]🧵 Strings Interessantes")
strings = r2.cmd('izz')
strings_destacadas = "\n".join([
    s for s in strings.splitlines()
    if any(x in s.lower() for x in ['flag', 'senha', 'key', 'secret', 'input'])
])
console.print(Panel(strings_destacadas or "Nenhuma string suspeita encontrada.", 
                    title="[magenta]Strings úteis", box=box.ROUNDED))

console.rule("[bold yellow]🧠 Analisando Funções Suspeitas")
functions = r2.cmdj('aflj')
report_md = []
report_aula = []

# Analisar especificamente a função main
main_func = next((f for f in functions if f['name'] == 'main'), None)
if main_func:
    addr = main_func['offset']
    r2.cmd(f's {addr}')
    disasm = r2.cmd('pdf')
    console.rule(f"[bold bright_white]🔍 main @ {hex(addr)}")

    # Checando se temos chamadas de rand() na main
    if "call sym.rand" in disasm or "call sym.imp.rand" in disasm:
        console.print("[yellow]Encontrada chamada para rand() na função main.")
        console.print("[yellow]Isso provavelmente exige replicar a lógica em C, usando a mesma libc (ou em Python c/ LCG idêntico).")

        # Gerar exploit automaticamente
        console.print("\n[bold yellow]Gerando exploit em C via GPT...\n")
        prompt_exploit = f"""
Você é um especialista em engenharia reversa. Atue e analise como um expert em reverse de CTF!
Aqui está o disassembly da função main de um binário que usa rand() para criptografar/descriptografar dados:

{disasm}

Gere um código C mínimo e funcional para explorar ou descriptografar (reproduzir a mesma lógica).
Explique sucintamente cada passo no código com comentários e use alocações simples.
Queremos apenas mostrar a flag em texto claro.
"""

        try:
            exploit_resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Você é um assistente especialista em engenharia reversa. "
                            "Recebe disassembly e deve gerar um exploit mínimo em C."
                        )
                    },
                    {"role": "user", "content": prompt_exploit}
                ]
            )
            exploit_code = exploit_resp.choices[0].message.content.strip()

            console.rule("[bold magenta]Exploit Gerado")
            console.print(Panel(Markdown(exploit_code), title="Código C para Explorar", box=box.ROUNDED))

            # Opcional: salvar em um arquivo .c
            exploit_file = "exploit.c"
            with open(exploit_file, "w") as f:
                f.write(exploit_code + "\n")
            console.print(f"[green]Exploit salvo em {exploit_file}")
        except Exception as ee:
            console.print(f"[red]Erro ao gerar exploit com GPT: {ee}")

    else:
        console.print("[green]Nenhuma chamada direta a rand() encontrada na função main.")
        console.print("[green]Devemos conseguir replicar a lógica em Python sem preocupação com divergência de rand().")

    prompt_func = (
        f"Analise a funcao main abaixo em assembly. Explique detalhadamente o que ela faz, "
        f"se ha alguma vulnerabilidade, e como explorar. Depois, explique de forma didatica "
        f"para iniciantes autistas em CTF, como o HTB. O objetivo e encontrar a flag escondida neste binario:\n\n{disasm}"
    )

    try:
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "Voce é um especialista em engenharia reversa e exploração de binarios."},
                {"role": "user", "content": prompt_func}
            ]
        )
        answer = resp.choices[0].message.content.strip()
        console.print(Panel(Markdown(answer), title=f"[green]main", box=box.ROUNDED))

        bullet_didatico = (
            f"### main @ {hex(addr)}\n"
            f"- Função main analisada automaticamente.\n"
            f"- Resultado da análise:\n  - " + answer.replace("\n", "\n  -") + "\n"
        )

        report_md.append(f"### main @ {hex(addr)}\n\n```asm\n{disasm}\n```\n\n{answer}\n")
        report_aula.append(bullet_didatico)

    except Exception as e:
        console.print(f"[red]Erro na função main: {e}")

# Escreve relatórios
with open("REloadAI_output.md", "w") as f:
    f.write("\n\n".join(report_md))

with open("REloadAI_Aula.md", "w") as f:
    f.write("\n\n".join(report_aula))

# Exportar para PDF
pdf = FPDF()
pdf.add_page()
pdf.set_font("Courier", size=10)
for bloco in report_md:
    for linha in bloco.split("\n"):
        try:
            # Evita erro de encoding do PDF se tiver caractere fora do latin-1
            pdf.multi_cell(0, 5, txt=linha.encode("latin-1", "replace").decode("latin-1"))
        except Exception:
            continue
pdf.output("REloadAI_output.pdf")

console.rule("[bold green]✅ Análise finalizada com sucesso")
console.print("Relatórios gerados: \n- REloadAI_output.md\n- REloadAI_Aula.md\n- REloadAI_output.pdf")
