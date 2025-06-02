# Visão Geral da Arquitetura REload.Me (Para Desenvolvedores)

Este documento fornece uma visão geral da arquitetura de software do REload.Me, com foco na estrutura modular do código e nas estratégias de extensibilidade. Ele é destinado a desenvolvedores que desejam entender, contribuir ou estender a plataforma.

## 1. Estrutura de Diretórios Principal (`src/`)

Conforme detalhado na Proposta de Nova Estrutura de Diretórios (`New_Directory_Structure_Proposal.md`), o código fonte principal do REload.Me reside no diretório `src/`. Esta estrutura visa promover a modularidade, separação de preocupações e facilitar a manutenção.

**Principais Subdiretórios em `src/`:**

*   **`src/api/`**: Contém a lógica da API REST FastAPI, incluindo routers, dependências e modelos de dados da API.
*   **`src/cli/`**: Código da Interface de Linha de Comando (CLI), provavelmente usando Typer ou Click.
*   **`src/common/`**: Módulos utilitários compartilhados por toda a aplicação (ex: logging, constantes, sanitização, manipulação de erros comuns).
*   **`src/config/`**: Gerenciamento de configurações da aplicação (ex: `settings.py` para carregar variáveis de ambiente, chaves de API).
*   **`src/core_orchestration/`**: Lógica central mínima para orquestrar as interações entre os diferentes módulos de análise e a interface do usuário. Pode incluir gerenciamento de tarefas ou pipelines de análise.
*   **`src/modules/`**: O coração da funcionalidade do REload.Me, com cada submódulo representando uma capacidade específica:
    *   **`src/modules/static_analysis/`**: Análise estática de binários (ex: `static_analyzer.py` com a classe `BinaryAnalyzer`, interagindo com radare2).
    *   **`src/modules/dynamic_analysis/`**: Análise dinâmica (ex: `dynamic_analyzer.py` com a classe `DynamicAnalyzer` e backends para Docker, Frida, Unicorn; `simple_docker_runner.py`).
    *   **`src/modules/exploit_development/`**: Ferramentas e lógica para auxiliar no desenvolvimento de exploits (ex: `exploit_generator.py`, `rop_generator.py`, `bof_solver.py`, integração com Pwntools).
    *   **`src/modules/ai_assisted_tools/`**: Componentes que utilizam IA/LLMs (ex: `function_explainer.py` para explicações de código assembly).
    *   **`src/modules/reporting/` (Planejado):** Geração de relatórios em diferentes formatos (Markdown, PDF).
*   **`src/services/`**: Clientes para serviços externos (ex: APIs de LLM como OpenAI, bancos de dados, etc.).
*   **`src/web_ui/`**: Código da interface do usuário web, incluindo templates HTML (Jinja2), arquivos estáticos (CSS, JS) e a lógica do servidor web (se não totalmente coberta pela API FastAPI).

## 2. Filosofia de Design

*   **Modularidade:** Cada funcionalidade principal é encapsulada em seu próprio módulo dentro de `src/modules/` ou `src/services/`. Isso permite o desenvolvimento, teste e manutenção independentes desses componentes.
*   **Separação de Preocupações (SoC):** A interface do usuário (web, CLI), a lógica de negócios/análise e o acesso a dados/serviços são separados o máximo possível.
*   **Injeção de Dependência (Conceitual):** Onde apropriado, módulos devem receber suas dependências (ex: configurações, instâncias de outros serviços) em vez de depender de estados globais, facilitando testes e flexibilidade.
*   **APIs Internas Claras:** A comunicação entre os módulos deve, idealmente, ocorrer através de interfaces bem definidas.

## 3. Estratégia de Paralelismo e Plugins (Visão de Futuro)

Conforme detalhado no `Parallelism_Plugins_Analysis_Report.md`, a arquitetura modular foi projetada para suportar futuras melhorias de desempenho e extensibilidade:

### 3.1. Paralelismo

*   **Oportunidades Identificadas:**
    *   **Análise Estática:** Paralelização da análise de múltiplas funções, extração de diferentes tipos de informações (strings, símbolos, gadgets).
    *   **Análise Dinâmica:** Execução de diferentes testes ou configurações de sandbox em paralelo.
    *   **Tarefas de IA:** Múltiplas chamadas a APIs de LLM.
*   **Abordagens Sugeridas:** `multiprocessing`, `asyncio` (para I/O bound como chamadas de API), Celery para tarefas mais longas ou distribuídas (ex: análise de múltiplos binários).

### 3.2. Arquitetura de Plugins

*   **Objetivo:** Permitir que o REload.Me seja estendido com novas ferramentas de análise, backends de execução dinâmica, formatos de relatório, ou outras funcionalidades, sem modificar o núcleo da aplicação.
*   **Pontos de Extensão Propostos:**
    *   **Analisadores Estáticos Adicionais:** Plugins que implementam uma interface `StaticAnalysisPlugin`.
    *   **Backends de Análise Dinâmica:** Plugins que implementam `DynamicAnalysisBackend` (ex: para Qiling, novos emuladores).
    *   **Ferramentas de Fuzzing:** Plugins via `FuzzingPlugin`.
    *   **Formatos de Relatório:** Plugins via `ReportingPlugin`.
*   **Mecanismos de Carregamento:**
    *   Entry points (setuptools) para plugins instalados como pacotes Python.
    *   Descoberta de arquivos em um diretório `plugins/`.
*   **Desafios:** Interfaces estáveis, gerenciamento de dependências de plugins, segurança.

## 4. Interação entre Componentes (Exemplo de Fluxo de Análise)

1.  **Entrada (UI/API):** Usuário faz upload de um binário e seleciona opções de análise.
2.  **Orquestração (`core_orchestration`):** Recebe a requisição e inicia um pipeline de análise.
3.  **Análise Estática (`static_analysis.BinaryAnalyzer`):**
    *   radare2 é usado para desmontagem, extração de strings, símbolos, proteções, CFG.
    *   O código de funções relevantes é passado para `ai_assisted_tools.AIFunctionExplainer`.
4.  **Assistência de IA (`ai_assisted_tools.AIFunctionExplainer`):**
    *   Envia o código para um LLM (OpenAI API ou Ollama local) para explicação e sugestão de vulnerabilidades.
5.  **Análise Dinâmica (`dynamic_analysis.DynamicAnalyzer` - se solicitada):**
    *   Executa o binário em um backend (Docker, Frida, Unicorn).
    *   Coleta traces, logs, etc.
    *   Resultados podem ser enviados para módulos de IA para sumarização de comportamento.
6.  **Desenvolvimento de Exploit (`exploit_development` - se o usuário prosseguir para esta fase):**
    *   Ferramentas como `bof_solver`, `rop_generator` são usadas.
    *   `ExploitGenerator` (com IA) pode sugerir exploits.
    *   (Futuro) Integração com `pwntools` via `ExploitSession` ou console de scripting.
7.  **Resultados e Relatórios:**
    *   Os resultados de todas as análises são agregados.
    *   O módulo de relatórios (futuro `src/modules/reporting`) formata os dados nos templates Jinja2 para visualização na UI ou download (Markdown, PDF).

Este overview é um guia para desenvolvedores. Detalhes específicos de cada módulo e interface serão documentados em seus respectivos arquivos de design ou no código.
