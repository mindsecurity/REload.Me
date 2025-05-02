# REload.Me – Engenharia Reversa com IA

**REload.Me** é uma plataforma automatizada de engenharia reversa assistida por inteligência artificial. Ela combina análise estática, dinâmica, visualizações avançadas e geração automática de exploits com uma interface poderosa para CTFs, Red Team e pesquisa.

---

## ✨ Funcionalidades Principais

- 🔍 Análise Estática com Radare2
- 🧠 Geração de Exploits via GPT + Templates
- 🧵 Detecção de Strings Sensíveis e Proteções
- 📊 Visualização Interativa 3D do Fluxo de Controle
- ⚙️ Resolução Automática de BoFs 32/64 bits
- 🔐 Fingerprints (ssdeep, imphash, tlsh)
- 📄 Relatórios Técnicos e Executivos (Jinja2 + WeasyPrint)
- 🧪 Integração com testes unitários e sandboxing

---

## 🚀 Como Usar

```bash
# Instala dependências e prepara ambiente
./install.sh

# Análise de binário simples
python -m reloadai.cli.reloadai_cli -f ./desafios/chall

# Força análise profunda (gasta mais RAM/CPU)
python -m reloadai.cli.reloadai_cli -f ./desafios/chall --deep
```