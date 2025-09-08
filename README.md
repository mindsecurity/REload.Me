# ReloadMe

[![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue)](https://www.python.org/)
[![Rich](https://img.shields.io/badge/terminal-rich%20UI-7957d5)](https://github.com/Textualize/rich)
[![Typer](https://img.shields.io/badge/CLI-typer-6cc24a)](https://github.com/tiangolo/typer)

REload.Me é uma CLI em Python para análise estática inicial de binários (PE e ELF), com coleta via r2pipe, apresentação com rich e mentoria opcional por LLM.

- Comando principal: `reloadme analyse|analyze <caminho_para_o_binario>`
- Objetivo: preparar terreno, organizar dados e oferecer insights para análise dinâmica.

## Recursos (V1)

- Informações do binário (iI/iIj): bintype, class, machine, bits, endian, os, subsystem, static, stripped, PIC, RELRO, rpath, runpath, interpreter.
- Checksec (ij → bin.sec): Canary, NX, PIE, ASLR, RELRO, Fortify.
- Funções principais: entrypoint real (iej/ij) e nomes-chave (main, entry0, _start, WinMain).
- Todas as funções (aflj): endereço (VA), size, realsz, nbbs, calltype/cc, nargs, nome.
- Strings (izj): amostra das principais strings.
- Pseudocódigo C da main: r2ghidra (pdgj/pdg) com fallback (pdc/pdr/pdd).
- Mentoria por IA (OpenAI): resumo e próximos passos com base nos dados coletados.


## Instalação

1) Criar e ativar um virtualenv Python 3.9+ e instalar o pacote em modo editable:

```
pip install -e .
```

2) Dependências Python principais: `r2pipe`, `pefile`, `rich`, `typer`, `openai`.

3) Decompilação (opcional): para usar r2ghidra (*r2pm -i r2ghidra*) (`pdg`/`pdgj`), garanta o plugin disponível no ambiente do r2 utilizado pelo r2pipe. Sem ele, o sistema tenta fallbacks (`pdc`, `pdr`, `pdd`).

## Uso

```
reloadme analyse ./exemplo.bin
reloadme analyze ./exemplo.bin
```

Fluxo de saída (em ordem):
- Informações do Binário (iI)
- Features de Segurança (checksec)
- Funções Principais
- Todas as Funções (aflj)
- Strings (top 50)
- Pseudocódigo C da main (quando disponível)
- Análise do Mentor de IA (opcional)

## Configuração da IA (OpenAI)

Defina a variável `OPENAI_API_KEY` ou crie um arquivo `.r2ai.openai-key` contendo a chave na primeira linha.

Linux/macOS:
```
export OPENAI_API_KEY="sua_chave"
```

Windows (PowerShell):
```
$env:OPENAI_API_KEY="sua_chave"
```

Arquivo `.r2ai.openai-key` (CWD ou HOME):
```
sk-...sua_chave...
```

Se a chamada à API falhar, a execução continua e apenas a análise local é exibida.

