# Roadmap de Desenvolvimento do REload.Me

Este documento descreve o plano de desenvolvimento para o REload.Me, desde a versão atual (considerada v0.2 após a fase de planejamento estratégico) até a visão para a v1.0.

---

## Visão Geral das Fases

*   **v0.1 (Concluída):** Prova de conceito inicial, funcionalidades básicas de análise estática e exploração de ideias com IA.
*   **v0.2 (Atual - Fundação Refatorada e Planejamento Estratégico - Resultado das Etapas 1-10 do Plano):**
    *   Revisão e fortalecimento da mensagem central e narrativa.
    *   Nova arquitetura de diretórios modular (`src/modules/`).
    *   Movimentação inicial de módulos do `core/` para a nova estrutura.
    *   Correções de importações e consolidação da `BinaryAnalyzer`.
    *   Definição e design conceitual do "CTF Mode" e "Modo Guiado".
    *   Análise e estratégia de integração do `pwntools`.
    *   Aprimoramento da funcionalidade de explicação de funções com IA (`AIFunctionExplainer`).
    *   Avaliação de tecnologias de IA (Ollama local vs. APIs de LLM) e recomendação estratégica.
    *   Estruturação e esboço do conteúdo inicial do Gibook Educacional.
    *   Revisão e refinamento dos planos de monetização.
    *   Proposta de ideias para engajamento comunitário (badges, repositório de exploits, Hall da Fama).
    *   Aprimoramento dos templates de relatório (executivo e técnico).
    *   Revisão de nomenclatura, branding e estratégia SEO.
    *   Criação de checklist de validação e templates de Issue/PR.
    *   Atualização da documentação principal (README, docs) e este Roadmap.
    *   **Foco:** Planejamento estratégico, refatoração da base de código, design conceitual de funcionalidades chave, e criação de artefatos de apoio ao desenvolvimento e comunidade. **Esta fase é majoritariamente de planejamento e documentação, com refatoração de código para suportar os próximos passos.**

---

## Próximas Versões e Metas

### REload.Me v0.3 (Protótipo Funcional Mínimo - Foco: UI e Análise Estática)

*   **Objetivo Principal:** Ter uma primeira versão da interface web funcional, permitindo ao usuário interagir com as capacidades de análise estática e a IA de explicação de funções.
*   **Principais Entregas:**
    *   **Interface Web (Frontend):**
        *   Implementação da UI básica para o **Modo Laboratório** (upload de binário, visualização de informações do arquivo, desmontagem, strings, proteções).
        *   Integração visual do `AIFunctionExplainer`: permitir que o usuário selecione uma função e veja a explicação da IA na UI.
    *   **Backend e Core:**
        *   API robusta para suportar o upload de binários e as funcionalidades de análise estática expostas na UI.
        *   `static_analyzer.py` (com `BinaryAnalyzer`) totalmente funcional para as tarefas requeridas pela UI.
        *   Configuração de API keys para OpenAI (ou outro LLM) de forma segura.
    *   **Modo CTF (Protótipo Inicial):**
        *   Funcionalidade de upload de binário específico para um "desafio CTF".
        *   Apresentação da análise estática inicial.
        *   Sistema de anotações manuais persistentes por desafio.
        *   Integração básica da IA para "explicar código" em trechos selecionados no contexto CTF.
    *   **Instalação e Deploy Simplificados:** Build Docker funcional para fácil execução da plataforma (backend + frontend básico).

### REload.Me v0.4 (Expansão da Análise e Interatividade - Foco: Dinâmica e Exploração Inicial)

*   **Objetivo Principal:** Introduzir capacidades de análise dinâmica na UI e as primeiras ferramentas interativas para desenvolvimento de exploits.
*   **Principais Entregas:**
    *   **Análise Dinâmica no Modo Laboratório:**
        *   Integração da UI para configurar e executar análise dinâmica básica (via `dynamic_analyzer.py`, começando com o backend Docker).
        *   Visualização dos resultados da análise dinâmica (traces de syscalls, logs de execução).
    *   **Integração Inicial de Pwntools:**
        *   Implementação conceitual da `ExploitSession` (ou similar) no Modo Laboratório ou num novo "Console de Exploração".
        *   Permitir envio de payloads e interação básica com processos (localmente) usando `pwntools` por baixo dos panos, controlado pela UI.
    *   **Modo Guiado (Primeiros Módulos):**
        *   Desenvolvimento e implementação dos primeiros 2-3 módulos de aprendizado no Modo Guiado (ex: "Introdução ao Assembly x86", "Buffer Overflow Básico").
        *   Interface para navegação e progresso nos módulos.
    *   **Gibook:** Publicação dos primeiros capítulos e integração de links contextuais da UI para o Gibook.

### REload.Me v0.5 - v0.8 (Modularidade, Comunidade e IA Avançada)

Esta fase será dividida em sub-releases (v0.5, v0.6, etc.) e focará em expandir a robustez, funcionalidades e o ecossistema.

*   **v0.5: Arquitetura de Plugins e Backends Dinâmicos:**
    *   Implementação da arquitetura de plugins (conforme `Parallelism_Plugins_Analysis_Report.md`).
    *   Adição de suporte a mais backends de análise dinâmica como plugins (ex: Frida, Unicorn com maior integração na UI).
*   **v0.6: Paralelismo e Otimização:**
    *   Implementação de paralelismo nas tarefas de análise identificadas (ex: análise de múltiplas funções, extração de dados).
    *   Otimização de performance geral da plataforma.
*   **v0.7: Funcionalidades de Comunidade (Beta):**
    *   Lançamento da primeira versão do sistema de Badges (Cyber-Crestas) e Hall da Fama.
    *   Implementação do Repositório Ético de Exploits (com submissão e moderação básica).
    *   Criação de um fórum de discussão ou servidor Discord/Telegram oficial.
*   **v0.8: IA Local e Expansão do Conteúdo:**
    *   Implementação do suporte opcional para Ollama, permitindo aos usuários usar modelos de IA locais.
    *   Expansão significativa do Gibook com mais capítulos e desafios.
    *   Mais laboratórios e desafios no Modo CTF.
    *   Refinamento das funcionalidades de IA existentes e introdução de novas (ex: sumarização de comportamento de malware, detecção de ofuscação).

### REload.Me v0.9 (Beta)

*   **Objetivo Principal:** Estabilização da plataforma, coleta extensiva de feedback e preparação para o lançamento oficial.
*   **Principais Entregas:**
    *   Todas as funcionalidades "core" planejadas para v1.0 implementadas e testadas.
    *   Ciclos de teste com a comunidade (alpha/beta testers).
    *   Correção intensiva de bugs e otimizações de usabilidade.
    *   Documentação final (Gibook, API docs, User Manuals) completa e revisada.
    *   Polimento da UI/UX.
    *   Preparação de materiais de marketing e lançamento.

### REload.Me v1.0 (Lançamento Estável)

*   **Objetivo Principal:** Uma plataforma robusta, bem documentada, com uma comunidade inicial engajada, pronta para uso público mais amplo.
*   **Principais Entregas:**
    *   Versão estável de todas as funcionalidades definidas até v0.9.
    *   Infraestrutura de suporte ao usuário (documentação, FAQs, canais de ajuda da comunidade).
    *   Planos de monetização ativos e claros.
    *   Estratégias de engajamento comunitário em pleno funcionamento.
    *   Um produto que efetivamente ajuda a "desvendar, aprender e colaborar" no campo da engenharia reversa.

---

Este roadmap é um guia e está sujeito a adaptações conforme o desenvolvimento avança e o feedback da comunidade é incorporado. O foco contínuo será em fornecer valor educacional e ferramentas poderosas para todos os níveis de usuários interessados em engenharia reversa.
