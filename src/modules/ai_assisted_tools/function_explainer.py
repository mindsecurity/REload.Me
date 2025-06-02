import openai
from typing import Optional, Dict
# Assuming a config module or environment variable for API key
# For now, API key will be passed as an argument.

class AIFunctionExplainer:
    """
    Uses an AI model (like OpenAI's GPT) to provide a detailed explanation
    of an assembly function.
    """

    def __init__(self, openai_api_key: Optional[str] = None):
        if openai_api_key:
            openai.api_key = openai_api_key
        # TODO: Add a check here if API key is None and potentially raise an error
        # or disable AI features if no key is available globally or passed.
        # For now, relies on openai.api_key being set globally if not passed.
        if not openai.api_key:
            print("Warning: OpenAI API key not set. AI Explainer may not function.")


    def _construct_prompt(self, assembly_code: str, architecture: str, function_address: Optional[str] = None) -> str:
        # Ensure assembly_code is not excessively long to avoid hitting token limits aggressively
        # This is a simplistic truncation, more sophisticated chunking might be needed for very long functions
        max_asm_length = 12000 # Character limit for assembly part of prompt (approx 3k-4k tokens)
        if len(assembly_code) > max_asm_length:
            assembly_code = assembly_code[:max_asm_length] + "\n... (assembly truncated due to length)"

        address_context = f"O endereço base da função é '{function_address}'." if function_address else "O endereço base da função não foi fornecido."

        prompt = f"""Você é um especialista em engenharia reversa e análise de segurança de software, com foco em didática para explicar conceitos complexos.
Analise a seguinte função assembly para a arquitetura '{architecture}' (ex: x86, x86_64, arm). {address_context}

Assembly da Função:
```asm
{assembly_code}
```

Por favor, forneça uma explicação detalhada que cubra os seguintes pontos, de forma clara e organizada:

1.  **Propósito Geral:**
    *   Qual o objetivo principal e a funcionalidade desta função em uma ou duas frases?

2.  **Entradas da Função:**
    *   Quais são os argumentos esperados? (Identifique-os a partir de registradores comuns de passagem de argumentos como RDI, RSI, RDX, RCX para x86_64, ou da stack [ebp+offset]).
    *   Como cada argumento identificado parece ser utilizado pela função?

3.  **Saídas da Função:**
    *   Qual o valor de retorno principal? (Normalmente em RAX para x86_64 ou EAX para x86).
    *   O que este valor de retorno representa?
    *   A função modifica dados em memória ou outros registradores que podem ser considerados saídas secundárias?

4.  **Fluxo de Trabalho Detalhado:**
    *   Descreva passo a passo a lógica principal da função.
    *   Explique blocos de código importantes, loops (com sua condição de parada, se aparente) e estruturas condicionais (if/else).
    *   Destaque operações aritméticas, lógicas ou de manipulação de bits chave.

5.  **Chamadas a Sub-rotinas (Calls):**
    *   Liste todas as instruções `call` para outras funções (identificadas por endereço ou nome simbólico, se disponível no disassembly).
    *   Para cada chamada, qual o propósito aparente dessa sub-rotina no contexto desta função?

6.  **Uso de Dados e Interação com Memória:**
    *   Como a função acessa ou manipula a memória (stack, heap, seções de dados)?
    *   Há referências a strings literais, constantes importantes ou estruturas de dados conhecidas? Se sim, quais e como são usadas?
    *   Descreva o setup do stack frame (prólogo) e sua limpeza (epílogo), se visível.

7.  **Potenciais Vulnerabilidades de Segurança:**
    *   Com base no código fornecido, identifique quaisquer padrões de código que possam levar a vulnerabilidades de segurança comuns. Seja específico sobre o tipo de vulnerabilidade (ex: Buffer Overflow, Format String, Integer Overflow/Underflow, Condição de Corrida, Use-after-free, etc.).
    *   Destaque as instruções ou sequências de código problemáticas.
    *   Se nenhuma vulnerabilidade óbvia for encontrada, mencione isso.

8.  **Sugestões de Renomeação (Opcional):**
    *   Com base na sua análise, sugira nomes mais descritivos para esta função ou para variáveis/registradores importantes, se os nomes atuais forem genéricos (ex: `sub_401000`, `var_4h`).

9.  **Resumo Conciso:**
    *   Forneça uma sinopse de 2-3 frases resumindo a função, seu impacto e quaisquer descobertas críticas.

Formate a saída de maneira clara, usando tópicos ou seções para cada um dos pontos acima. Se o assembly for muito longo ou complexo para uma análise exaustiva de cada ponto, foque nos aspectos mais relevantes e de maior impacto.
"""
        return prompt

    def explain_function(self, assembly_code: str, architecture: str, function_address: Optional[str] = None, model: str = "gpt-4o") -> Optional[str]:
        """
        Envia o código assembly de uma função para a API da OpenAI e retorna a explicação.

        Args:
            assembly_code: String contendo o código assembly da função.
            architecture: Arquitetura do código (ex: "x86_64", "x86", "arm").
            function_address: Endereço opcional da função para contexto.
            model: Modelo da OpenAI a ser usado (ex: "gpt-4o", "gpt-4-turbo").

        Returns:
            String contendo a explicação formatada ou None em caso de erro.
        """
        if not openai.api_key:
            return "Erro: Chave da API OpenAI não configurada."

        prompt = self._construct_prompt(assembly_code, architecture, function_address)

        try:
            # print(f"---- DEBUG PROMPT ----\n{prompt}\n---- END DEBUG PROMPT ----") # For debugging
            response = openai.chat.completions.create(
                model=model,
                messages=[
                    # O prompt já contém a instrução de sistema no seu corpo.
                    # Se preferir, pode separar:
                    # {"role": "system", "content": "Você é um especialista em engenharia reversa..."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3, # Temperatura mais baixa para respostas mais factuais e menos "criativas"
                max_tokens=2048, # Ajustar conforme necessário para o tamanho da resposta
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Erro ao chamar a API da OpenAI: {e}")
            return f"Erro ao processar a explicação da IA: {e}"

if __name__ == '__main__':
    # Exemplo de uso (requer que a variável de ambiente OPENAI_API_KEY esteja configurada)
    # Ou passe a chave diretamente: explainer = AIFunctionExplainer(openai_api_key="sk-...")
    
    # Tente carregar a chave de uma variável de ambiente se não for passada
    # Em um app real, isso viria de um config mais robusto
    import os
    api_key_env = os.getenv("OPENAI_API_KEY")
    if not api_key_env:
        print("Por favor, defina a variável de ambiente OPENAI_API_KEY para rodar este exemplo.")
        print("Ex: export OPENAI_API_KEY='your_key_here'")
    else:
        explainer = AIFunctionExplainer(openai_api_key=api_key_env)

        # Exemplo de código assembly (função simples que soma dois números em x86_64)
        example_asm_x86_64 = """
        _add_numbers:
            push rbp
            mov rbp, rsp
            mov eax, edi  ; Argumento 1 em edi (Linux x86_64 ABI)
            add eax, esi  ; Argumento 2 em esi
            pop rbp
            ret
        """
        print("--- Explicando função x86_64 (Soma) ---")
        explanation = explainer.explain_function(example_asm_x86_64, "x86_64", "_add_numbers")
        if explanation:
            print(explanation)
        print("\\n" + "="*50 + "\\n")

        # Exemplo de código assembly (função com loop e potencial vulnerabilidade)
        example_asm_vulnerable_x86 = """
        _vulnerable_func:
            push ebp
            mov ebp, esp
            sub esp, 0x40     ; Aloca 64 bytes no stack para 'buffer'
            lea eax, [ebp-0x40] ; Carrega endereço de 'buffer' em eax
            push eax          ; Passa 'buffer' como argumento para gets
            call _gets        ; Chama gets (vulnerável!)
            add esp, 0x4      ; Limpa argumento da stack
            nop
            leave
            ret
        _gets: ; dummy gets for testing
            ret 
        """
        print("--- Explicando função x86 (Vulnerável com gets) ---")
        explanation_vuln = explainer.explain_function(example_asm_vulnerable_x86, "x86", "_vulnerable_func")
        if explanation_vuln:
            print(explanation_vuln)

        # Para testar com um modelo diferente, se disponível e configurado:
        # explanation_gpt4o = explainer.explain_function(example_asm_x86_64, "x86_64", "_add_numbers", model="gpt-4o")
        # if explanation_gpt4o:
        #     print("\\n--- GPT-4o ---")
        #     print(explanation_gpt4o)
