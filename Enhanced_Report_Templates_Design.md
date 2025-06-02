## Design Aprimorado dos Templates de Relatório do REload.Me

Este documento detalha a análise dos templates de relatório existentes e propõe estruturas e conteúdos aprimorados para os relatórios executivo e técnico gerados pelo REload.Me.

### 1. Análise dos Templates de Relatório Existentes

Foram analisados os arquivos `templates/report_exec.md.j2` e `templates/report_tech.md.j2`.

*   **`report_exec.md.j2` (Atual):**
    *   Parece ser um template combinado ou uma versão mais antiga que tenta cobrir tanto aspectos executivos quanto técnicos.
    *   Inclui informações básicas do arquivo, um sumário estático, proteções, strings e um loop por "funções críticas" com desmontagem e explicação (IA).
    *   A segunda metade do arquivo intitula-se "Relatório Técnico", duplicando algumas informações e adicionando fingerprints e detalhes do CFG.
    *   **Variáveis Jinja2 Notáveis:** `meta`, `protecoes`, `packer`, `checksec`, `strings`, `funcoes`, `version`, `fingerprints`, `cfg`.

*   **`report_tech.md.j2` (Atual):**
    *   Mais focado, apresentando informações como nome do arquivo, hashes, proteções, lista parcial de funções, desmontagem da `main`, comentários da IA para `main`, alguns gadgets ROP e o CFG em formato DOT.
    *   **Variáveis Jinja2 Notáveis:** `meta`, `fp`, `protecoes`, `functions`, `main_disasm`, `main_ia`, `rop`, `cfg_dot`.

**Conclusão da Análise:** Os templates atuais precisam de uma clara separação de propósitos. O relatório executivo deve ser conciso e focado em impacto, enquanto o técnico deve ser detalhado e abrangente. O template `report_exec.md.j2` atual tenta fazer ambos e precisa ser dividido.

### 2. Proposta de Conteúdo e Estrutura para Relatório Executivo Aprimorado

*   **Público-Alvo:** Gestores, C-level, pessoal não técnico ou com pouco tempo.
*   **Objetivo:** Fornecer uma visão geral rápida dos riscos e do estado do binário analisado.

**Estrutura Proposta (`report_executive_v2.md.j2`):**

```markdown
# Relatório Executivo de Análise de Segurança – REload.Me

**Data da Análise:** {{ analysis_datetime | date("dd/MM/yyyy HH:mm") }}

## 1. Identificação do Artefato Analisado
*   **Nome do Arquivo:** `{{ file_info.name }}`
*   **SHA256:** `{{ file_info.sha256 }}`
*   **Tamanho:** {{ file_info.size_kb }} KB
*   **Tipo Inferido:** {{ file_info.type | default("Não determinado") }}

## 2. Resumo Geral da Análise
> Esta seção apresenta uma visão consolidada dos achados mais significativos e o propósito inferido do binário.

*   **Propósito Inferido do Binário (Assistência IA):** {{ ai_summary.inferred_purpose | default("Não foi possível inferir um propósito específico automaticamente.") }}
*   **Principais Descobertas Críticas:**
    *   {% if summary.critical_vulnerabilities_count > 0 %}Presença de {{ summary.critical_vulnerabilities_count }} vulnerabilidade(s) crítica(s) identificada(s).{% else %}Nenhuma vulnerabilidade crítica diretamente identificada pela análise automatizada.{% endif %}
    *   {% if summary.sensitive_data_found %}Identificação de potenciais dados sensíveis (strings, chaves).{% endif %}
    *   {% if summary.is_packed %}O binário aparenta estar empacotado/ofuscado, dificultando a análise.{% endif %}
*   **Comentário da IA sobre o Binário (Alto Nível):** {{ ai_summary.overall_assessment | default("Análise de IA de alto nível não disponível.") }}

## 3. Avaliação de Risco
> Classificação do nível de risco com base nas descobertas automatizadas.

*   **Nível de Risco Estimado:** **{{ summary.risk_level | upper }}** 
    *   *(Valores Possíveis: Baixo, Médio, Alto, Crítico)*
*   **Justificativa Breve:** {{ summary.risk_justification | default("Baseado nas vulnerabilidades e características identificadas.") }}

## 4. Achados de Maior Impacto (Top 3)
> Detalhamento conciso dos problemas mais relevantes e seu possível impacto no negócio ou na segurança.

{% if top_findings %}
    {% for finding in top_findings limit:3 %}
1.  **Achado:** {{ finding.title }}
    *   **Descrição Breve:** {{ finding.description }}
    *   **Impacto Potencial:** {{ finding.impact }}
    {% endfor %}
{% else %}
*   Nenhum achado de alto impacto destacado pela análise automatizada.
{% endif %}

## 5. Recomendações Estratégicas
> Ações de alto nível sugeridas com base nos resultados da análise.

*   {% if summary.risk_level in ['ALTO', 'CRÍTICO'] %}Recomenda-se uma investigação técnica detalhada e imediata deste artefato.{% endif %}
*   {% if summary.is_packed %}Considerar técnicas de desempaquetamento para uma análise mais profunda.{% endif %}
*   Revisar as permissões e o contexto de execução deste binário no ambiente produtivo.
*   Para uma análise completa, consulte o **Relatório Técnico Completo** (`{{ technical_report_filename }}`).

---
Relatório gerado por REload.Me v{{ app_version }} em {{ analysis_datetime | date("dd/MM/yyyy") }}.
```

**Variáveis Jinja2 Esperadas (para Relatório Executivo):**
*   `analysis_datetime`
*   `file_info`: Objeto com `name`, `sha256`, `size_kb`, `type`.
*   `ai_summary`: Objeto com `inferred_purpose`, `overall_assessment`.
*   `summary`: Objeto com `critical_vulnerabilities_count`, `sensitive_data_found` (booleano), `is_packed` (booleano), `risk_level` (string), `risk_justification`.
*   `top_findings`: Lista de objetos, cada um com `title`, `description`, `impact`.
*   `technical_report_filename`
*   `app_version`

### 3. Proposta de Conteúdo e Estrutura para Relatório Técnico Aprimorado

*   **Público-Alvo:** Analistas de segurança, desenvolvedores, engenheiros reversos.
*   **Objetivo:** Fornecer todos os detalhes técnicos relevantes coletados e gerados pela análise.

**Estrutura Proposta (`report_technical_v2.md.j2`):**

```markdown
# Relatório Técnico de Análise de Binário – REload.Me

**Data da Análise:** {{ analysis_datetime | date("dd/MM/yyyy HH:mm") }}

## 1. Informações do Arquivo
*   **Nome do Arquivo:** `{{ file_info.name }}`
*   **MD5:** `{{ file_info.md5 }}`
*   **SHA1:** `{{ file_info.sha1 }}`
*   **SHA256:** `{{ file_info.sha256 }}`
*   **SSDeep:** `{{ file_info.ssdeep | default("N/A") }}`
*   **TLSH:** `{{ file_info.tlsh | default("N/A") }}`
*   **Tamanho:** {{ file_info.size_bytes }} bytes ({{ file_info.size_kb }} KB)
*   **Tipo (magic):** `{{ file_info.type }}`
*   **Arquitetura:** `{{ file_info.arch }}` ({{ file_info.bits }} bits)
*   **Endianness:** `{{ file_info.endianness }}`
*   **Entry Point:** `{{ file_info.entry_point | hex }}`
*   **Empacotador Detectado:** `{{ file_info.packer | default("Nenhum ou não detectado") }}`

## 2. Detalhes da Análise Estática

### 2.1. Proteções de Segurança (Checksec)
```
{{ static_analysis.checksec_output | default("Informação de Checksec não disponível.") }}
```
*   **Canary:** {{ static_analysis.protections.canary | default("Desconhecido") }}
*   **NX (DEP):** {{ static_analysis.protections.nx | default("Desconhecido") }}
*   **PIE (ASLR):** {{ static_analysis.protections.pie | default("Desconhecido") }}
*   **RELRO:** {{ static_analysis.protections.relro | default("Desconhecido") }}
*   **Fortify:** {{ static_analysis.protections.fortify | default("Desconhecido") }}

### 2.2. Strings Relevantes
*(Strings que correspondem a padrões de interesse. Para todas as strings, consulte o apêndice ou a saída JSON.)*
{% if static_analysis.interesting_strings %}
    | Endereço   | Tipo    | String                               |
    |------------|---------|--------------------------------------|
    {% for s in static_analysis.interesting_strings limit:20 %}
    | `{{ s.address | hex }}` | {{ s.type }} | `{{ s.string | truncate(80) }}` |
    {% endfor %}
    {% if static_analysis.interesting_strings | length > 20 %}
    *... e mais {{ (static_analysis.interesting_strings | length) - 20 }} strings.*
    {% endif %}
{% else %}
*   Nenhuma string particularmente interessante detectada automaticamente.
{% endif %}

### 2.3. Símbolos e Bibliotecas Importadas
*   **Principais Bibliotecas Importadas:**
    {% if static_analysis.imported_libraries %}
        {% for lib in static_analysis.imported_libraries %}
        *   `{{ lib }}`
        {% endfor %}
    {% else %}
    *   Nenhuma biblioteca importada identificada ou aplicável.
    {% endif %}
*   **Principais Funções Importadas (Exemplos):**
    {% if static_analysis.imported_functions %}
        {% for func in static_analysis.imported_functions limit:15 %}
        *   `{{ func.name }}` (da {{ func.library | default("libc") }})
        {% endfor %}
    {% else %}
    *   Nenhuma função importada identificada.
    {% endif %}
*   **Funções Exportadas (se houver):**
    {% if static_analysis.exported_functions %}
        {% for func in static_analysis.exported_functions limit:10 %}
        *   `{{ func.name }}` (`{{ func.address | hex }}`)
        {% endfor %}
    {% else %}
    *   Nenhuma função exportada.
    {% endif %}

### 2.4. Análise de Funções (com Assistência IA)
{% if static_analysis.analyzed_functions %}
    {% for func_analysis in static_analysis.analyzed_functions %}
#### Função: `{{ func_analysis.name }}` (`{{ func_analysis.address | hex }}`)
*   **Tamanho:** {{ func_analysis.size }} bytes
*   **Complexidade Ciclomática (CC):** {{ func_analysis.cyclomatic_complexity | default("N/A") }}
*   **Desmontagem (Trecho Inicial):**
    ```{{ func_analysis.arch | default("assembly") }}
    {{ func_analysis.disassembly_snippet | truncate(500, True) }}
    ```
*   **Explicação da IA:**
    > {{ func_analysis.ai_explanation | indent(4) | default("Explicação da IA não disponível para esta função.") }}
*   **Vulnerabilidades Sugeridas pela IA:**
    {% if func_analysis.ai_vulnerabilities %}
        {% for vuln in func_analysis.ai_vulnerabilities %}
        *   **Tipo:** {{ vuln.type }} - **Severidade:** {{ vuln.severity | default("Desconhecida") }}
            *   **Descrição:** {{ vuln.description }}
        {% endfor %}
    {% else %}
    *   Nenhuma vulnerabilidade específica sugerida pela IA para esta função.
    {% endif %}
    ---
    {% endfor %}
{% else %}
*   Nenhuma função analisada individualmente com IA neste relatório.
{% endif %}

### 2.5. Gadgets ROP (Amostra)
{% if static_analysis.rop_gadgets %}
    | Endereço   | Gadget Instrução(ões)          |
    |------------|--------------------------------|
    {% for gadget in static_analysis.rop_gadgets limit:10 %}
    | `{{ gadget.address | hex }}` | `{{ gadget.instruction }}` |
    {% endfor %}
    {% if static_analysis.rop_gadgets | length > 10 %}
    *... e mais {{ (static_analysis.rop_gadgets | length) - 10 }} gadgets.*
    {% endif %}
{% else %}
*   Nenhum gadget ROP encontrado ou esta análise não foi executada.
{% endif %}

### 2.6. Grafo de Controle de Fluxo (CFG) - Função Principal
{% if static_analysis.main_cfg_dot %}
*Visualização do CFG para `{{ static_analysis.main_function_name }}` (formato DOT):*
```dot
{{ static_analysis.main_cfg_dot }}
```
*(Este grafo pode ser renderizado usando ferramentas como Graphviz.)*
{% else %}
*   CFG da função principal não gerado.
{% endif %}

## 3. Detalhes da Análise Dinâmica
{% if dynamic_analysis %}
### 3.1. Ambiente de Execução
*   **Backend Utilizado:** {{ dynamic_analysis.backend_type | default("Não especificado") }}
*   **Imagem (se Docker):** {{ dynamic_analysis.docker_image | default("N/A") }}
*   **Timeout de Execução:** {{ dynamic_analysis.timeout_seconds }} segundos

### 3.2. Comportamento Observado
*   **Log de Execução (Trecho):**
    ```
    {{ dynamic_analysis.execution_log_snippet | truncate(1000, True) | default("Nenhum log de execução capturado.") }}
    ```
*   **Principais Chamadas de Sistema (Syscalls) (Amostra):**
    {% if dynamic_analysis.syscall_summary %}
        | Syscall         | Contagem | Argumentos Comuns (Exemplo) |
        |-----------------|----------|-----------------------------|
        {% for syscall in dynamic_analysis.syscall_summary limit:15 %}
        | `{{ syscall.name }}` | {{ syscall.count }} | `{{ syscall.example_args | truncate(50) }}` |
        {% endfor %}
    {% else %}
    *   Nenhuma syscall monitorada ou registrada.
    {% endif %}
*   **Interações de Rede:**
    {% if dynamic_analysis.network_activity %}
        {% for net_op in dynamic_analysis.network_activity limit:10 %}
        *   **Operação:** {{ net_op.type }} - **Destino:** `{{ net_op.destination }}` - **Dados (prévia):** `{{ net_op.data_preview | truncate(50) }}`
        {% endfor %}
    {% else %}
    *   Nenhuma atividade de rede detectada.
    {% endif %}
*   **Operações de Arquivo:**
    {% if dynamic_analysis.file_operations %}
        {% for file_op in dynamic_analysis.file_operations limit:10 %}
        *   **Operação:** {{ file_op.type }} - **Caminho:** `{{ file_op.path }}` - **Permissões:** `{{ file_op.mode | default("") }}`
        {% endfor %}
    {% else %}
    *   Nenhuma operação de arquivo significativa detectada.
    {% endif %}

### 3.3. Comportamentos Suspeitos Detectados pela IA
{% if dynamic_analysis.ai_suspicious_behaviors %}
    {% for behavior in dynamic_analysis.ai_suspicious_behaviors %}
*   **Descrição:** {{ behavior.description }}
    *   **Severidade Estimada:** {{ behavior.severity }}
    *   **Evidência/Detalhes:** {{ behavior.evidence | truncate(100) }}
    {% endfor %}
{% else %}
*   Nenhum comportamento especificamente marcado como suspeito pela IA durante a análise dinâmica.
{% endif %}
{% else %}
*   Análise dinâmica não foi executada ou não produziu resultados.
{% endif %}

## 4. Vulnerabilidades Identificadas (Consolidado)
{% if vulnerabilities %}
    {% for vuln in vulnerabilities %}
### 4.{{ loop.index }} {{ vuln.name | default("Vulnerabilidade Indefinida") }}
*   **Tipo:** {{ vuln.type | default("Desconhecido") }}
*   **Severidade Estimada:** {{ vuln.severity | default("Não Avaliada") }} (CVSS: {{ vuln.cvss_score | default("N/A") }})
*   **Localização:** Função `{{ vuln.function_name | default("N/A") }}` no endereço `{{ vuln.address | hex | default("N/A") }}`
*   **Descrição Detalhada:**
    {{ vuln.description | indent(4) }}
*   **Evidência/Prova de Conceito (PoC):**
    ```{{ vuln.poc_language | default("text") }}
    {{ vuln.poc_code | default("Nenhuma PoC fornecida.") }}
    ```
*   **Sugestões de Mitigação Técnica:**
    {{ vuln.mitigation_steps | indent(4) | default("Nenhuma sugestão de mitigação específica fornecida.") }}
---
    {% endfor %}
{% else %}
*   Nenhuma vulnerabilidade específica foi identificada ou detalhada neste relatório.
{% endif %}

## 5. Conclusão Técnica e Recomendações
*   **Resumo Técnico:** {{ technical_summary | default("Revisar os detalhes acima para um entendimento completo.") }}
*   **Próximos Passos Sugeridos para Investigação/Correção:**
    {% if next_steps %}
        {% for step in next_steps %}
        *   {{ step }}
        {% endfor %}
    {% else %}
    *   Revisar manualmente as seções de vulnerabilidades e comportamentos suspeitos.
    *   Considerar análise mais aprofundada com ferramentas especializadas se necessário.
    {% endif %}

---
Relatório gerado por REload.Me v{{ app_version }} em {{ analysis_datetime | date("dd/MM/yyyy") }}.
(Para dados completos, consulte a saída JSON: `{{ json_report_filename }}`)
```

**Variáveis Jinja2 Esperadas (para Relatório Técnico):**
*   `analysis_datetime`
*   `file_info`: Objeto com `name`, `md5`, `sha1`, `sha256`, `ssdeep`, `tlsh`, `size_bytes`, `size_kb`, `type`, `arch`, `bits`, `endianness`, `entry_point`, `packer`.
*   `static_analysis`: Objeto contendo:
    *   `checksec_output`: String completa do checksec.
    *   `protections`: Objeto com `canary`, `nx`, `pie`, `relro`, `fortify`.
    *   `interesting_strings`: Lista de objetos (`address`, `type`, `string`).
    *   `imported_libraries`: Lista de strings.
    *   `imported_functions`: Lista de objetos (`name`, `library`).
    *   `exported_functions`: Lista de objetos (`name`, `address`).
    *   `analyzed_functions`: Lista de objetos (`name`, `address`, `size`, `cyclomatic_complexity`, `disassembly_snippet`, `arch`, `ai_explanation`, `ai_vulnerabilities` (lista de objetos)).
    *   `rop_gadgets`: Lista de objetos (`address`, `instruction`).
    *   `main_cfg_dot`: String do CFG em formato DOT para a função principal.
    *   `main_function_name`: Nome da função principal.
*   `dynamic_analysis` (opcional): Objeto contendo:
    *   `backend_type`, `docker_image`, `timeout_seconds`.
    *   `execution_log_snippet`.
    *   `syscall_summary`: Lista de objetos (`name`, `count`, `example_args`).
    *   `network_activity`: Lista de objetos (`type`, `destination`, `data_preview`).
    *   `file_operations`: Lista de objetos (`type`, `path`, `mode`).
    *   `ai_suspicious_behaviors`: Lista de objetos (`description`, `severity`, `evidence`).
*   `vulnerabilities`: Lista de objetos (`name`, `type`, `severity`, `cvss_score`, `function_name`, `address`, `description`, `poc_language`, `poc_code`, `mitigation_steps`).
*   `technical_summary`: String.
*   `next_steps`: Lista de strings.
*   `app_version`
*   `json_report_filename`

### 4. Sugestões para Templates Jinja2

*   **Uso de Loops:**
    *   `{% for item in items %}` para listas como `top_findings`, `interesting_strings`, `analyzed_functions`, `vulnerabilities`, etc.
    *   Usar `loop.index` para numeração (ex: `4.{{ loop.index }}`).
    *   Usar `limit:N` filtro para mostrar apenas os N primeiros itens em resumos (ex: `static_analysis.rop_gadgets limit:10`).
*   **Condicionais:**
    *   `{% if condition %}` ... `{% else %}` ... `{% endif %}` para seções opcionais (ex: análise dinâmica, lista de vulnerabilidades se vazia).
    *   Verificar se uma variável existe ou tem valor antes de usá-la (ex: `{{ file_info.packer | default("Nenhum") }}`).
*   **Filtros Jinja2:**
    *   `| date("dd/MM/yyyy HH:mm")` para formatar datas.
    *   `| round(1)` para arredondar números.
    *   `| upper` para maiúsculas.
    *   `| hex` (custom filter, se necessário, ou pré-formatado no contexto) para endereços.
    *   `| truncate(80)` para encurtar strings longas.
    *   `| indent(4)` para formatar blocos de texto (como explicações da IA ou PoCs).
    *   `| default("mensagem padrão")` para valores que podem estar ausentes.
    *   `| length` para obter o tamanho de listas e controlar mensagens de "e mais X itens".
*   **Includes (Opcional):** Para seções muito repetitivas ou complexas, `{% include 'partial_template.md.j2' %}` pode ser usado.
*   **Whitespace Control:** Usar `{{- ... -}}` para remover espaços em branco antes/depois de blocos Jinja2, se necessário para melhor formatação do Markdown.

### 5. Considerações sobre Conversão para PDF

*   **WeasyPrint:**
    *   Já está listado em `requirements.txt`. É uma boa escolha para converter HTML (que pode ser gerado a partir do Markdown) para PDF.
    *   Requer que o Markdown seja primeiro convertido para HTML. Uma biblioteca Python como `Markdown` (`pip install markdown`) pode ser usada.
    *   CSS será essencial para estilizar o PDF. Um arquivo CSS dedicado precisará ser criado e referenciado.
*   **Pandoc:**
    *   Uma ferramenta de linha de comando universal para conversão de documentos.
    *   Pode converter Markdown diretamente para PDF, geralmente usando LaTeX como intermediário (requer uma instalação LaTeX).
    *   Permite o uso de templates LaTeX customizados para controle total sobre a aparência do PDF.
    *   Também pode gerar HTML (que poderia ser usado com WeasyPrint).
*   **Considerações para Boa Conversão:**
    *   **CSS para HTML/WeasyPrint:** Definir estilos para cabeçalhos, tabelas, blocos de código, listas, etc. Controlar quebras de página.
    *   **Templates LaTeX (para Pandoc):** Se for necessário um controle muito fino (ex: cabeçalhos/rodapés complexos, numeração específica), criar um template LaTeX é o caminho.
    *   **Tratamento de Blocos de Código:** Garantir que o syntax highlighting do Markdown seja preservado ou renderizado corretamente no PDF.
    *   **Imagens e Grafos:** Grafos DOT precisarão ser convertidos para imagens (PNG, SVG) antes da inclusão no PDF. Ferramentas como `dot -Tpng G.dot -o G.png` (do Graphviz) podem ser chamadas.
    *   **Quebras de Página:** Usar CSS (`page-break-before`, `page-break-after`) ou comandos LaTeX para controlar quebras de página e evitar tabelas ou seções cortadas.

**Recomendação:** Para o REload.Me, começar com a conversão **Markdown -> HTML -> PDF via WeasyPrint** parece o caminho mais direto, dado que WeasyPrint já é uma dependência. Isso permite usar CSS para estilização, que é uma habilidade web comum. Se necessidades mais complexas de formatação surgirem, Pandoc com LaTeX pode ser explorado.

### 6. Conclusão

As propostas acima visam tornar os relatórios do REload.Me significativamente mais úteis e adaptados aos seus respectivos públicos. A estrutura modular com Jinja2 permitirá a fácil inclusão de novos dados de análise conforme a ferramenta evolui.
