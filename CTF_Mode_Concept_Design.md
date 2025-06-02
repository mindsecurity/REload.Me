## Design Conceitual do "CTF Mode" para REload.Me (Protótipo Inicial)

Este documento descreve as funcionalidades chave, o fluxo de usuário e o design conceitual para um protótipo inicial do "CTF Mode" na plataforma REload.Me. O foco é no upload de binários de desafios CTF e em um sistema de anotação assistido por Inteligência Artificial.

### 1. Fluxo de Usuário para o "CTF Mode" (Protótipo Inicial)

1.  **Seleção do Modo:**
    *   Na interface principal do REload.Me (Dashboard ou menu), o usuário (tipicamente a persona "Bruno, o Analista Jr." ou "Ana, a Estudante" que está progredindo) seleciona a opção "Modo CTF" ou "Resolver Desafio CTF".

2.  **Criação/Seleção de Sessão CTF:**
    *   O usuário pode ver uma lista de desafios CTF anteriores nos quais trabalhou.
    *   Opção para "Iniciar Novo Desafio CTF". Ao selecionar, é solicitado um nome para o desafio (ex: "PwnMe_BoF_Easy", "ACME_Corp_Rev100").

3.  **Upload do Binário:**
    *   Uma interface de upload permite ao usuário arrastar e soltar ou selecionar o arquivo binário do desafio CTF.
    *   Validações básicas do arquivo (ex: tamanho, tipo, se é um executável) são realizadas.

4.  **Análise Automática Inicial:**
    *   Após o upload, o REload.Me executa automaticamente uma análise estática inicial usando o módulo `static_analyzer.py` (`BinaryAnalyzer`).
    *   **Informações Extraídas:**
        *   Informações básicas do arquivo (arquitetura, bits, formato).
        *   Verificação de proteções (Canary, NX, PIE, RELRO).
        *   Extração de strings (com destaque para as potencialmente interessantes).
        *   Lista de funções (nomes, endereços, tamanhos).
        *   (Opcional, configurável) Geração de um grafo de chamadas básico.
    *   Um feedback visual (ex: barra de progresso) é exibido durante esta análise.

5.  **Apresentação da Interface do Desafio ("CTF Workspace"):**
    *   Após a análise inicial, a interface principal do "CTF Mode" é carregada (detalhes no item 3).
    *   O desmontado da função `main` (ou `entry0`, ou a primeira função encontrada) é exibido por padrão no painel central.
    *   Informações resumidas do binário (proteções, arquitetura) são visíveis.
    *   A lista de funções e strings está disponível para navegação.

6.  **Interação, Análise e Anotação:**
    *   O usuário navega pela lista de funções, selecionando uma para ver seu desmontado.
    *   O usuário pode selecionar linhas de código no desmontador, endereços, ou nomes de função/variável.
    *   Ao selecionar, um menu de contexto aparece, oferecendo ações manuais (ex: "Adicionar Anotação Manual") e ações assistidas por IA (detalhes no item 2).
    *   As anotações (manuais ou geradas pela IA e aceitas pelo usuário) são exibidas e podem ser gerenciadas.
    *   O usuário pode tentar identificar vulnerabilidades, entender a lógica do programa e formular uma estratégia de exploração.

7.  **(Futuro) Transição para Exploração:**
    *   Após identificar uma vulnerabilidade e coletar informações relevantes (offsets, gadgets, etc.) através da análise e anotações, o usuário pode optar por desenvolver um exploit (detalhes no item 4).

8.  **Salvar Sessão:**
    *   Todo o progresso, incluindo anotações e estado da análise, é salvo automaticamente ou através de uma ação explícita, associado à sessão CTF nomeada.

### 2. Funcionalidade de Anotação Assistida por IA

Esta funcionalidade é central para o "CTF Mode", ajudando o usuário a entender o binário e a identificar pontos cruciais.

*   **Ativação:**
    *   O usuário seleciona um elemento na interface:
        *   Uma ou mais linhas de código no visualizador de desmontagem.
        *   Um nome de função na lista de funções.
        *   Um endereço específico (ex: em uma string, em um operando de instrução).
        *   Uma string identificada na lista de strings.
    *   Após a seleção, um menu de contexto (clique direito ou um ícone flutuante) oferece opções, incluindo um submenu "Assistência da IA".

*   **Ações da IA (Exemplos):**
    *   **`IA: Explicar este código/função`**:
        *   A IA fornece um resumo em linguagem natural do propósito do bloco de código ou função selecionada.
        *   Para Ana: Explicação mais básica, focada em conceitos.
        *   Para Bruno: Explicação mais técnica, focada na lógica e possíveis efeitos colaterais.
    *   **`IA: Identificar possíveis vulnerabilidades aqui`**:
        *   A IA analisa o trecho selecionado (ou a função inteira) em busca de padrões de vulnerabilidades conhecidas (ex: uso de `gets`, `strcpy` sem limites, inteiros vulneráveis, format strings, etc.).
        *   Destaca a linha específica e descreve o tipo de vulnerabilidade potencial.
    *   **`IA: Sugerir pontos de interesse nesta função`**:
        *   A IA destaca chamadas de sistema importantes (`syscall`), loops complexos, seções de código que manipulam entrada do usuário, ou lógica condicional incomum.
    *   **`IA: O que este dado/string significa?`**:
        *   Se uma string ou constante é selecionada, a IA tenta inferir seu propósito (ex: "Esta string parece ser uma mensagem de erro", "Este valor é usado como tamanho de buffer"). Pode verificar se a string é uma chave de API conhecida, base64, etc.
    *   **`IA: Renomear variável/função com base no uso`**:
        *   Sugere nomes mais descritivos para variáveis ou funções com base na análise do seu uso e interações.
    *   **`IA: Gerar pseudocódigo`**:
        *   Converte o bloco de assembly selecionado em uma representação de pseudocódigo de alto nível.

*   **Sistema de Anotações:**
    *   **Apresentação das Sugestões da IA:**
        *   As sugestões/explicações da IA aparecem em um painel dedicado ou como pop-ups não intrusivos.
        *   Cada sugestão tem botões: "Adicionar às Anotações", "Editar e Adicionar", "Ignorar".
    *   **Anotações Manuais:**
        *   O usuário pode clicar com o botão direito em qualquer endereço, linha de código, ou função e selecionar "Adicionar Anotação".
        *   Um editor de texto simples permite inserir notas. As anotações podem suportar tags ou categorias (ex: "Vulnerabilidade", "Lógica Importante", "TODO").
    *   **Visualização e Gerenciamento:**
        *   As anotações são visualmente indicadas no desmontador (ex: um ícone ao lado da linha).
        *   O painel esquerdo ("Anotações do Usuário") lista todas as anotações, permitindo filtrar, buscar e navegar para a localização da anotação no código.
        *   As anotações são salvas persistentemente com a sessão CTF.

### 3. Esboço da Interface do "CTF Mode" ("CTF Workspace")

*   **Layout Principal (Conceito de 3 Painéis + Barra de Ferramentas):**

    ```
    +--------------------------------------------------------------------------------------------------+
    | [Barra de Ferramentas: Upload Binário | Iniciar Análise Profunda (Opc) | Abrir Lab Exploit | Salvar ] |
    +--------------------------------------------------------------------------------------------------+
    | Painel Esquerdo (Navegação e Info) | Painel Central (Visualizador Principal)                       |
    |                                    |                                                               |
    | [Tabs: Funções, Strings, Símbolos] | [Tabs: Desmontagem: main | func_X | ...]                     |
    | - func_A @ 0x401000 (anotada)      |   0x401000: push ebp                                          |
    | - func_B @ 0x401080                |   0x401001: mov ebp, esp (linha selecionada)                  |
    | - ...                              |   0x401003: sub esp, 0x10                                     |
    |                                    |   ... (com syntax highlighting)                               |
    | [Tabs: Anotações do Usuário]       |                                                               |
    | - Vuln: BoF em func_A @ 0x401020   |                                                               |
    | - TODO: Verificar xrefs de func_C  |                                                               |
    | - ...                              |                                                               |
    |                                    | [Sub-Painel: Strings Referenciadas / Xrefs da linha atual]    |
    +------------------------------------|---------------------------------------------------------------|
    | Painel Inferior/Direito (Interação e Output da IA)                                               |
    |                                                                                                  |
    | [Tabs: Assistente IA | Anotação Manual | Console Pwntools (Futuro) | Output do Binário (Futuro)]  |
    | > IA: A função 'strcpy' nesta linha pode ser vulnerável a buffer overflow.                     |
    |   [Adicionar Anotação] [Editar] [Ignorar]                                                        |
    |                                                                                                  |
    | Anotação Manual para 0x401001: "Ponto de entrada da função, setup do stack frame." [Salvar]       |
    |                                                                                                  |
    +--------------------------------------------------------------------------------------------------+
    ```

*   **Painel Esquerdo (Navegação e Info):**
    *   **Tabs:** "Funções", "Strings", "Símbolos Globais", "Proteções".
    *   Lista de itens clicáveis. Clicar em uma função abre seu desmontado no Painel Central.
    *   Indicadores visuais para itens com anotações.
    *   Uma tab separada ou seção para "Minhas Anotações", listando todas as anotações do usuário, pesquisáveis e filtráveis. Clicar em uma anotação leva à sua localização no código.

*   **Painel Central (Visualizador Principal):**
    *   Visualizador de desmontagem com abas para diferentes funções ou visualizações (ex: Hexdump).
    *   Syntax highlighting para assembly.
    *   Capacidade de selecionar linhas, endereços, operandos.
    *   Ao selecionar, um menu de contexto aparece para "Adicionar Anotação Manual" ou invocar "Assistência da IA".
    *   Scroll-linked com outras visualizações (ex: um futuro visualizador de stack ou hexdump).
    *   (Opcional) Pequeno sub-painel abaixo do desmontador para mostrar strings ou referências cruzadas (xrefs) para a instrução/endereço selecionado.

*   **Painel Direito (ou Inferior - configurável pelo usuário):**
    *   **Tab "Assistente IA":** Exibe as explicações, sugestões e análises da IA. Permite ao usuário interagir com as sugestões (aceitar, editar, ignorar).
    *   **Tab "Anotação Manual":** Um campo de texto para o usuário adicionar/editar anotações para o item selecionado no Painel Central. Botão "Salvar Anotação".
    *   **(Futuro) Tab "Console Pwntools/Debug":** Um console interativo para executar comandos `pwntools` ou interagir com um depurador (GDB).
    *   **(Futuro) Tab "Output do Binário":** Para ver o stdout/stderr de execuções do binário de desafio.

*   **Barra de Ferramentas Superior:**
    *   Botão "Upload Novo Binário".
    *   Botão "Salvar Sessão CTF".
    *   (Opcional) Botão "Iniciar Análise Dinâmica" (para uma fase posterior do CTF Mode).
    *   Botão "Abrir no Laboratório de Exploit" (para transição para desenvolvimento de exploit).

*   **Interação Geral:**
    *   Cliques com o botão direito em funções, linhas de código, strings, etc., abrem menus contextuais.
    *   A interface deve ser responsiva, permitindo redimensionar painéis.

### 4. Integração com `pwntools` (Conceitual no "CTF Mode")

O "CTF Mode" foca primariamente na análise e anotação. A transição para o desenvolvimento ativo de exploits com `pwntools` seria um passo seguinte, possivelmente levando a um ambiente mais especializado.

*   **Coleta de Informações para `pwntools`:**
    *   Durante a análise no "CTF Mode", o usuário (com ajuda da IA) coleta informações cruciais para o exploit:
        *   Offsets de buffer overflow (ex: `bof_solver.py` pode ser invocado internamente).
        *   Endereços de funções úteis (ex: `win()`, `system()`, `gets()@plt`).
        *   Endereços de gadgets ROP (ex: via `rop_generator.py` ou a futura integração com `pwntools.ROP`).
        *   Conteúdo de strings para leaks de memória (ex: canary, endereços da libc).
    *   Estas informações seriam salvas nas anotações.

*   **Transição para "Laboratório de Exploit":**
    *   Um botão na barra de ferramentas: **"Criar Exploit Script"** ou **"Abrir no Laboratório de Exploit"**.
    *   Ao clicar, o REload.Me poderia:
        1.  Abrir uma nova área/modo (o "Modo Laboratório" focado em scripting, ou um console Python integrado como proposto para Clara).
        2.  **Pré-popular um script de exploit:** Gerar um script Python básico usando `pwntools` e as informações coletadas nas anotações.
            *   Exemplo de script pré-populado:
                ```python
                from pwn import *

                # Contexto do binário (preenchido automaticamente)
                elf_path = "./nome_do_binario_ctf" # Caminho para o binário no servidor ou workspace
                elf = ELF(elf_path)
                context.binary = elf
                # context.log_level = 'debug' # Opcional

                # Informações coletadas (das anotações)
                offset_eip = 112 # Exemplo de anotação
                addr_win_func = elf.symbols.get('win', 0x0) # Exemplo
                # rop_gadget_pop_rdi = 0xdeadbeef # Exemplo

                # Conexão (local por padrão, configurável para remote)
                # io = process(elf.path)
                # io = remote(" endereço_ctf ", porta) 
                # Esta parte seria configurável na UI do Laboratório de Exploit

                payload = b''
                payload += b'A' * offset_eip
                if addr_win_func:
                    payload += p64(addr_win_func)
                # else:
                    # payload += p64(rop_gadget_pop_rdi)
                    # payload += p64(elf.got['puts']) # Exemplo para leak
                    # payload += p64(elf.plt['puts'])
                    # payload += p64(elf.symbols['main'])

                # print("Payload:", payload)
                # io.sendline(payload)
                # io.interactive()
                
                # TODO: Adicionar lógica de interação e envio do payload
                log.info("Script base gerado. Preencha a lógica de interação e payload.")
                ```
        3.  Fornecer a interface `ExploitSession` (proposta na tarefa anterior) para interações mais estruturadas se o usuário preferir em vez de um script `pwntools` puro.

*   **Uso das Anotações:** O sistema de "Criar Exploit Script" leria as anotações categorizadas (ex: "offset_bof", "addr_gadget_pop_rdi", "addr_func_win") para preencher variáveis no template do script.

### 5. Conclusão

O "CTF Mode" inicial se concentraria em fornecer um ambiente de análise estática robusto, enriquecido com um sistema de anotações inteligente e assistido por IA. Isso permitiria aos usuários entenderem os desafios de forma eficiente e prepararem o terreno para o desenvolvimento de exploits, para o qual uma transição suave para um ambiente baseado em `pwntools` seria fornecida. A IA atua como um guia e um acelerador, sem remover o controle do usuário.
