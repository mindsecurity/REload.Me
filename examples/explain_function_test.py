import argparse
import os
import r2pipe
import sys
from typing import Optional, Tuple

# Ajustar o sys.path para permitir importações de 'src'
# Isso é comum em scripts de exemplo/teste fora do diretório principal do pacote
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
sys.path.insert(0, project_root)

from src.modules.ai_assisted_tools.function_explainer import AIFunctionExplainer

def get_function_disassembly(binary_path: str, function_identifier: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Usa r2pipe para obter o código assembly de uma função e sua arquitetura.
    Retorna (assembly, architecture, address_hex) ou (None, None, None) em caso de erro.
    """
    r2 = None
    try:
        r2 = r2pipe.open(binary_path)
        r2.cmd('aaa') # Analisar tudo para identificar funções

        # Obter informações do binário para arquitetura
        bin_info = r2.cmdj('ij')
        if not bin_info or 'bin' not in bin_info:
            print(f"Erro: Não foi possível obter informações do binário {binary_path}")
            return None, None, None
        
        arch = bin_info['bin'].get('arch', 'unknown')
        bits = bin_info['bin'].get('bits', 32) # Default to 32 if not found
        
        # Tentar resolver o identificador da função para um endereço
        # Isso pode ser um nome (main, sym.main, fcn.00401000) ou um endereço direto (0x401000)
        r2.cmd(f"s {function_identifier}") # Seek para o identificador
        
        # Verificar se o seek foi bem-sucedido e obter o endereço atual e nome da função
        current_seek_info = r2.cmdj('sjj') # Get current seek address info
        if not current_seek_info or not current_seek_info[0].get('offset'):
             # Tentar 'aflj' para encontrar a função pelo nome se o seek falhar (ex: nome curto como 'main')
            functions_info = r2.cmdj('aflj')
            target_func_info = None
            if functions_info:
                for func in functions_info:
                    if func.get('name') == function_identifier or func.get('name','').endswith('.'+function_identifier) :
                        target_func_info = func
                        break
            if not target_func_info:
                print(f"Erro: Função '{function_identifier}' não encontrada no binário.")
                return None, None, None
            func_addr = target_func_info.get('offset')
            r2.cmd(f"s {func_addr}") # Seek para o endereço encontrado
        else:
            func_addr = current_seek_info[0].get('offset')

        # Obter desmontagem da função no endereço atual
        disassembly = r2.cmd('pdf') # pdf no endereço atual

        if not disassembly:
            print(f"Erro: Não foi possível obter o disassembly para a função '{function_identifier}' no endereço {hex(func_addr)}.")
            return None, None, None

        # Determinar arquitetura completa (ex: x86_64)
        architecture_full = arch
        if arch == "x86" and bits == 64:
            architecture_full = "x86_64"
        
        return disassembly, architecture_full, hex(func_addr)

    except Exception as e:
        print(f"Erro ao interagir com r2pipe: {e}")
        return None, None, None
    finally:
        if r2:
            r2.quit()

def main():
    parser = argparse.ArgumentParser(description="Testa o AIFunctionExplainer para explicar uma função de um binário.")
    parser.add_argument("binary_path", help="Caminho para o arquivo binário.")
    parser.add_argument("function_id", help="Nome ou endereço da função a ser explicada (ex: main, 0x401000).")
    parser.add_argument("--model", help="Modelo OpenAI a ser usado (ex: gpt-4o, gpt-4-turbo)", default="gpt-4o")
    
    args = parser.parse_args()

    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        print("Erro: A variável de ambiente OPENAI_API_KEY não está definida.")
        print("Por favor, defina-a antes de executar o script.")
        print("Ex: export OPENAI_API_KEY='your_key_here'")
        sys.exit(1)

    print(f"Analisando a função '{args.function_id}' no binário '{args.binary_path}'...")
    
    disassembly, architecture, func_addr_hex = get_function_disassembly(args.binary_path, args.function_id)

    if disassembly and architecture:
        print(f"\\n--- Disassembly de '{args.function_id}' ({architecture} @ {func_addr_hex}) ---")
        print(disassembly)
        print("--- Fim do Disassembly ---\\n")

        explainer = AIFunctionExplainer(openai_api_key=openai_api_key)
        print(f"Solicitando explicação da IA (modelo: {args.model})...")
        explanation = explainer.explain_function(disassembly, architecture, func_addr_hex, model=args.model)

        if explanation:
            print("\\n--- Explicação da IA ---")
            print(explanation)
            print("--- Fim da Explicação ---")
        else:
            print("Não foi possível obter a explicação da IA.")
    else:
        print("Não foi possível obter o disassembly da função.")

if __name__ == "__main__":
    # Exemplo de como rodar (requer que a chave OPENAI_API_KEY esteja no ambiente):
    # python examples/explain_function_test.py tests/tests/test_vulnerable main
    # python examples/explain_function_test.py /bin/ls main 
    main()
