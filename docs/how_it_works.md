# Como Funciona o REload.Me

O pipeline do REload.Me segue uma abordagem multi-camada e modular:

---

## 🧼 1. Sanitização do Binário

- Valida extensão, tamanho, tipo MIME e SHA256
- Detecta packers comuns (UPX, Themida)
- Extrai fingerprints: ssdeep, imphash, tlsh

---

## 🧠 2. Análise Estática

- Usa Radare2 para extrair funções, call graph e instruções
- Detecta funções perigosas (`strcpy`, `system`, `rand`)
- Extrai gadgets ROP curtos (`/Rj 3`)
- Constrói visualização 3D (Plotly + NetworkX)

---

## 🤖 3. IA Explainer + Exploit Generator

- Pergunta ao GPT-4o (ou modelo local) sobre a função `main`
- Explica cada parte como um professor de CTF
- Sugere exploits automáticos para rand(), gets(), etc
- Gera código Python ou C de prova de conceito

---

## 🧪 4. BoF Solver

- Detecta offset automaticamente via padrões cíclicos (`cyclic_find`)
- Sugere payloads automáticos (overflow com shellcode)
- Gera exploit pronto em Python com pwntools (em breve)

---

## 📄 5. Relatórios e Visualizações

- Dashboard HTML interativo com grafo 3D e metadados
- Relatórios Markdown e PDF usando Jinja2 + WeasyPrint

---

## 🔬 Módulos Avançados

- `dynamic.py`: análise dinâmica (em construção)
- `ctf_solver.py`: heurísticas para desafios de CTF
- `malware_generator.py`: geração de payloads para red team
- `binary_differ.py`: comparação entre dois binários