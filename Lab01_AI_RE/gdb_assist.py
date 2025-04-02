import argparse
import pexpect
import requests
import subprocess
import os

PROMPT_TEMPLATE_PATH = "prompt_templates/comment_function.txt"
OUTPUT_PATH = "ai_output/main_analysis.txt"

def extract_main_function(binary_path):
    """Usa GDB via pexpect para extrair a funcao main do binario."""
    gdb = pexpect.spawn(f"gdb {binary_path}", encoding='utf-8')
    gdb.expect("\(gdb\)")
    gdb.sendline("disassemble main")
    gdb.expect("\(gdb\)")
    output = gdb.before
    gdb.sendline("quit")
    return output

def clean_gdb_output(raw_output):
    """Remove linhas irrelevantes do disassembly da main."""
    lines = raw_output.splitlines()
    clean_lines = [line for line in lines if ":" in line and not line.strip().startswith("Breakpoint")]
    return "\n".join(clean_lines)

def load_prompt_template():
    with open(PROMPT_TEMPLATE_PATH, "r") as f:
        return f.read()

def save_output(text):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write(text)

def query_chatgpt_local(prompt):
    """Substitua isso pelo seu comando local do ChatGPT."""
    result = subprocess.run(["chatgpt-local"], input=prompt, text=True, capture_output=True)
    return result.stdout

def query_ollama(prompt):
    response = requests.post("http://localhost:11434/api/generate", json={
        "model": "mistral",
        "prompt": prompt,
        "stream": False
    })
    return response.json()["response"]

def main():
    parser = argparse.ArgumentParser(description="Extração e análise da funcao main via IA")
    parser.add_argument("--bin", required=True, help="Caminho para o binário")
    parser.add_argument("--llm", choices=["chatgpt", "ollama"], default="chatgpt", help="LLM a ser usado")
    args = parser.parse_args()

    print("[+] Extraindo funcao main do binario...")
    raw = extract_main_function(args.bin)
    code = clean_gdb_output(raw)
    prompt_template = load_prompt_template()
    final_prompt = prompt_template.replace("{function_code}", code)

    print(f"[+] Enviando para modelo {args.llm}...")
    if args.llm == "chatgpt":
        result = query_chatgpt_local(final_prompt)
    else:
        result = query_ollama(final_prompt)

    save_output(result)
    print(f"[+] Comentario salvo em {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
