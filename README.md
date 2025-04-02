# 🧠 REload.Me

**REload.Me** – *A aula de reverse mais fácil do mundo. Pra fazer todos entenderem de uma vez.*

Engenharia Reversa e Inteligência Artificial para quem pensa diferente. Descomplicando a exploração com LLMs.

---

## 🎯 Visão do Projeto

**REload.Me** é uma plataforma educacional hacker criada por e para pessoas neurodivergentes que querem aprender Engenharia Reversa, Exploitation e Red Team com o poder da Inteligência Artificial.

Utilizando Ghidra, GDB, LLMs (como chatGPT, Claude ou Ollama) e prompts personalizados, o projeto ensina como explorar binários de forma visual, didática e automatizada.

---

## 🔥 O que você vai aprender

- Como usar **LLMs para comentar automaticamente funções de binários**
- Renomear e facilitar o entendimento de código assembly o/
- Integração de **GDB + IA** para RE assistida
- Uso real de **prompt engineering ofensivo**
- Exploração assistida com storytelling prático
- Visualização no Ghidra com anotações automatizadas

---

## 🧱 Estrutura do Projeto

```
REload.Me/
├── Lab01_AI_RE/
│   ├── bin/
│   │   └── vuln-binary           # Binário vulnerável usado no lab
│   ├── gdb_assist.py            # Script que integra GDB + IA
│   ├── prompt_templates/
│   │   └── comment_function.txt # Template para comentar funções
│   ├── ai_output/               # Comentários gerados pela IA
│   └── docker-compose.yml       # Ambiente isolado com GDB + Python + Ollama opcional
├── branding/
│   ├── logo.png
│   ├── paleta-cores.md
│   └── fontes.md
├── site/
│   ├── index.html               # Landing page simples
│   └── style.css
└── README.md
```

---

## 🛠️ Stack Utilizada

- **GhidraMCP + ChatGPT / Claude AI**
- **GDB** também para inspeção de binários
- **Python 3.10+** com `pexpect` para controle de execução
- **Ollama (opcional)** para uso com LLMs locais (Mistral, LLaMA, etc)
- **Prompt Engineering** com sistema de templates

---

## 🧪 Primeiro Lab: "Comentando a main() com IA"

### Objetivo:
Pegar uma função `main()` descompilada e fazer a IA:
- Explicar o que a função faz passo a passo
- Sugerir possíveis vulnerabilidades (ex: buffer overflow)
- Criar rascunhos de exploit ou entradas de fuzz

### Exemplo de prompt:
```txt
Analyze the following C-like function extracted from a binary. Comment line-by-line what each instruction does, highlight possible vulnerabilities, and suggest how it could be exploited. Keep it simple, clear and practical.

{function_code}
```

Resultado esperado:
- Comentários automáticos salvos em `ai_output/main_analysis.txt`
- Código revisado pode ser importado para o Ghidra com anotações

---

## 💡 Por que esse projeto é diferente?

- Foco em **acessibilidade cognitiva** para autistas e neurodivergentes
- Materiais práticos e visuais
- Ferramentas que você realmente vai usar em CTFs, pentests e Red Team
- Ensino com IA real, não teoria

---

## 📬 Contato

Feito por **Marcos Tolosa**  
🔗 [LinkedIn](https://linkedin.com/in/marcos-tolosa) | 🧠 [HackTheBox Top 100](https://app.hackthebox.com/profile/44238)

---

Pronto para hackear a forma como você aprende Engenharia Reversa?  
**REload.Me é o seu novo ponto de partida.**
