# Como Funciona o REload.Me (Visão Geral da Arquitetura)

O REload.Me é projetado com uma arquitetura modular para facilitar a análise de binários e o desenvolvimento de exploits, com um forte componente de Inteligência Artificial para assistir em várias etapas. O fluxo de trabalho geral e os principais componentes são descritos abaixo.

## 1. Entrada e Configuração

*   **Upload do Binário:** O usuário inicia fornecendo um arquivo binário através de uma das interfaces (Modo Guiado, Laboratório, CTF, ou API).
*   **Configuração da Análise:** Dependendo do modo e das preferências do usuário, diferentes parâmetros de análise podem ser configurados (ex: profundidade da análise estática, backend de análise dinâmica, modelos de IA a serem usados).

## 2. Orquestração e Módulos Principais (`src/`)

O coração do REload.Me reside na sua estrutura modular localizada em `src/`, que permite flexibilidade e extensibilidade.

### 2.1. Módulo de Análise Estática (`src/modules/static_analysis/`)
*   **Componente Central:** `static_analyzer.py` (contendo a classe `BinaryAnalyzer`).
*   **Ações:**
    *   Utiliza `r2pipe` para interagir com o radare2.
    *   Extrai informações básicas do arquivo (tipo, arquitetura, proteções de segurança como NX, PIE, Canary, RELRO).
    *   Desmonta o código (disassembly).
    *   Identifica funções, strings, símbolos e referências cruzadas (xrefs).
    *   Gera Grafos de Controle de Fluxo (CFGs).
    *   Detecta packers ou ofuscação básica.
    *   Coleta dados para serem usados pela IA (ex: código assembly de funções).

### 2.2. Módulo de Análise Dinâmica (`src/modules/dynamic_analysis/`)
*   **Componente Central:** `dynamic_analyzer.py` (contendo a classe `DynamicAnalyzer`).
*   **Backends Suportados (Conceitual):** Docker (com `simple_docker_runner.py` ou lógica interna), Unicorn, Frida.
*   **Ações:**
    *   Executa o binário em um ambiente controlado e instrumentado (sandbox).
    *   Permite debugging (breakpoints, step-through).
    *   Coleta traços de execução: chamadas de sistema (syscalls), interações com arquivos e rede, alterações na memória.
    *   Identifica comportamento em tempo de execução.

### 2.3. Módulo de Ferramentas Assistidas por IA (`src/modules/ai_assisted_tools/`)
*   **Componente Central:** `function_explainer.py` (contendo `AIFunctionExplainer`).
*   **Ações:**
    *   Recebe código assembly (e contexto como arquitetura, endereço) do módulo de análise estática.
    *   Constrói prompts detalhados para LLMs (via API OpenAI ou futuramente Ollama local).
    *   Fornece explicações sobre: propósito da função, entradas/saídas, fluxo de trabalho, chamadas a sub-rotinas, uso de dados, potenciais vulnerabilidades, sugestões de renomeação.
    *   (Futuro) Outras ferramentas: detecção de padrões de vulnerabilidade, sumarização de comportamento de malware, sugestão de gadgets ROP contextuais.

### 2.4. Módulo de Desenvolvimento de Exploit (`src/modules/exploit_development/`)
*   **Componentes:** `exploit_generator.py`, `rop_generator.py`, `bof_solver.py`.
*   **Ações:**
    *   Utiliza `pwntools` (estratégia de integração definida) para interações, packing, ROP, shellcraft.
    *   `bof_solver`: Ajuda a encontrar offsets para buffer overflows (usando `pwntools.cyclic`).
    *   `rop_generator`: Ajuda a encontrar gadgets ROP (usando `r2pipe` e futuramente `pwntools.ROP`).
    *   `exploit_generator`: Usa templates e assistência de IA para gerar esqueletos de exploit.
    *   (Futuro) `ExploitSession`: Classe de abstração para facilitar a escrita de scripts de exploit.

### 2.5. Módulos Comuns e de Configuração (`src/common/`, `src/config/`)
*   **`src/common/`:** Contém utilitários compartilhados (logging, constantes, sanitização de entrada, etc.).
*   **`src/config/`:** Gerencia configurações da aplicação, incluindo chaves de API. (Nota: `config.py` ainda está na raiz, planejado para mover para `src/config/settings.py`).

## 3. Interfaces de Usuário (UX/UI)

O REload.Me é projetado com múltiplas interfaces para diferentes perfis de usuário:

*   **Modo Guiado:** Focado em aprendizado, com instruções passo a passo e explicações integradas (conteúdo do Gibook e IA).
*   **Modo Laboratório:** Ambiente gráfico interativo para análise estática/dinâmica e desenvolvimento de exploits assistido por IA.
*   **Modo Terminal Raw com AI Assist:** Interface de linha de comando avançada para controle total e scripting.
*   **Modo CTF:** Ambiente focado na resolução de desafios, com ferramentas de anotação e análise específicas.

## 4. Geração de Relatórios e Saídas

*   **Módulo de Relatórios (Futuro em `src/modules/reporting/`):**
    *   Utiliza templates Jinja2 (`templates/report_exec.md.j2`, `templates/report_tech.md.j2` - a serem atualizados conforme design).
    *   Consolida informações dos diversos módulos de análise.
    *   Gera relatórios em Markdown, com planos para conversão para PDF (ex: via WeasyPrint).

## 5. Integração com Gibook Educacional

*   O conteúdo do Gibook (`docs/educational_content/`) é referenciado contextualmente dentro da ferramenta para fornecer explicações mais profundas sobre conceitos e funcionalidades.
*   Desafios do Gibook podem ser carregados diretamente no Modo CTF.

## 6. Futuro: Arquitetura de Plugins e Paralelismo

*   A arquitetura modular visa facilitar a introdução de:
    *   **Plugins:** Para novos analisadores, backends de dinâmica, ferramentas de fuzzing, formatos de relatório.
    *   **Paralelismo:** Para acelerar análises de múltiplas funções, múltiplos binários ou diferentes configurações de análise dinâmica.

Este fluxo de trabalho e arquitetura permitem que o REload.Me seja uma plataforma flexível e poderosa, adaptando-se tanto a iniciantes quanto a especialistas em engenharia reversa.
