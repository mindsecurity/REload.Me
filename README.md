# REloadAI – Engenharia Reversa com IA (GPT-4o)

[![Python](https://img.shields.io/badge/Python-3.8%2B-green)](https://www.python.org/downloads/release/python-380/) [![radare2](https://img.shields.io/badge/radare2-%F0%9F%94%AE-red)](https://github.com/radareorg/radare2) [![OpenAI API](https://img.shields.io/badge/OpenAI-API-blue)](https://platform.openai.com/docs/introduction) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **O que é**: Um script Python para **análise de binários** (checksec, strings suspeitas, disassembly) usando **radare2** e **GPT** para gerar insights e até **exploits automáticos**.


## ✨ Funcionalidades Principais

- **Análise Inicial do Binário** (`checksec`, formato ELF/PE, strings suspeitas)
- **Análise de Funções**: Em especial `main` – desassembly completo, explicado passo a passo pelo GPT.
- **Geração Automática de Exploits**: Se for detectado o uso de `rand()` ou outra lógica pseudoaleatória, o GPT cria um *exploit em C* para reproduzir/romper a criptografia.
- **Relatórios Automatizados**: Produzimos
  - `REloadAI_output.md` (relatório técnico em Markdown)
  - `REloadAI_Aula.md` (explicações para iniciantes)
  - `REloadAI_output.pdf` (PDF para leitura offline)

## 🏁 Requisitos

1. **Python 3.8+**
2. **radare2** instalado ([Guia de Instalação](https://github.com/radareorg/radare2))
3. **Bibliotecas Python**:
   ```bash
   pip install r2pipe rich fpdf openai
   ```
4. **Chave de API** do [OpenAI](https://platform.openai.com/docs/introduction):
   - Salve em `~/.r2ai.openai-key`
   ```bash
   echo "sk-1234..." > ~/.r2ai.openai-key
   ```

## 🚀 Uso

```bash
python reloadai.py -f ./seu_binario_alvo
```

### Exemplos

1. **Analisar e gerar relatórios**:
   ```bash
   python reloadai.py -f ./rev_simpleencryptor/encrypt
   ```
2. **Verificar Exploit** (se encontrar `rand()` na `main`):
   - O script perguntará ao GPT para criar automaticamente um `exploit.c` e salvá-lo localmente.

## 📂 Estrutura de Saída

- **REloadAI_output.md**: Relatório detalhado com assembly e comentários do GPT.
- **REloadAI_Aula.md**: Tópicos para uma aula simplificada.
- **REloadAI_output.pdf**: Versão PDF do relatório.
- **exploit.c**: Se houver uso de `rand()`, o GPT gera automaticamente este arquivo.

## 🔧 Customização

- Se quiser analisar outra função além de `main`, ajuste o script no local onde definimos `main_func`.
- Para capturar mais strings, inclua outros termos na lista `['flag','key','secret',...]`.
- Ajuste o `prompt_exploit` se precisar de um estilo de exploit mais específico.

## 🤝 Contribuindo

1. Faça um **Fork**.
2. Crie uma nova **Branch**: `git checkout -b feature/sua-ideia`.
3. Commit suas mudanças: `git commit -m 'Adicionei uma feature'`.
4. Faça **Push** no seu fork: `git push origin feature/sua-ideia`.
5. Abra um **Pull Request** neste repositório.

## 📝 Licença

Este projeto está sob a licença [MIT](https://opensource.org/licenses/MIT). Fique à vontade para usar e modificar.

## 📢 Agradecimentos

- [radare2](https://github.com/radareorg/radare2) por fornecer uma suíte de engenharia reversa incrível.
- [OpenAI](https://platform.openai.com/docs/introduction) pela API que alimenta as explicações e geração de exploit.
- [Hack The Box](https://www.hackthebox.com/) pelo aprendizado prático em desafios de segurança.

---

**REloadAI** – Seu atalho para entender, explorar e **desvendar** binários de maneira super didática!

