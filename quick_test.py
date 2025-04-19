#!/usr/bin/env python3
"""
Teste de detecção de vulnerabilidades do REloadAI
"""
import os
import sys
import tempfile
from pathlib import Path
import traceback

# Adiciona diretório raiz ao path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Importa módulos necessários
from core.analyzer import BinaryAnalyzer
from rich.console import Console

console = Console()

def main():
    console.print("[bold blue]REloadAI - Teste de Detecção de Vulnerabilidades[/bold blue]")
    
    # Cria binário de teste com vulnerabilidades mais óbvias
    test_c_code = """
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    
    void vuln_function(char *input) {
        char buffer[32];
        strcpy(buffer, input);  // Vulnerabilidade proposital
        printf("Buffer: %s\\n", buffer);
    }
    
    void format_string_vuln(char *input) {
        printf(input);  // Format string vulnerability
    }
    
    void weak_crypto() {
        srand(1234);  // Fraca semente para PRNG
        int key = rand();
        printf("Chave gerada: %d\\n", key);
    }
    
    int main(int argc, char *argv[]) {
        if (argc < 2) {
            printf("Usage: %s <input>\\n", argv[0]);
            return 1;
        }
        
        vuln_function(argv[1]);
        format_string_vuln(argv[1]);
        weak_crypto();
        
        return 0;
    }
    """
    
    try:
        # Compila binário de teste
        console.print("\n[yellow]1. Compilando binário de teste com várias vulnerabilidades...[/yellow]")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Salva código fonte
            c_file = os.path.join(temp_dir, "test_vuln.c")
            with open(c_file, "w") as f:
                f.write(test_c_code)
            
            # Compila sem proteções para garantir vulnerabilidades
            binary_file = os.path.join(temp_dir, "test_vuln")
            compile_cmd = f"gcc -o {binary_file} {c_file} -fno-stack-protector -z execstack -no-pie"
            
            console.print(f"[cyan]Comando de compilação: {compile_cmd}[/cyan]")
            
            if os.system(compile_cmd) != 0:
                console.print("[red]Erro ao compilar binário de teste[/red]")
                return
            
            console.print("[green]✓ Binário compilado com sucesso[/green]")
            
            # Analisa binário com debug ativado
            console.print("\n[yellow]2. Analisando binário com debug ativado...[/yellow]")
            
            try:
                analyzer = BinaryAnalyzer(binary_file, debug=True)
                analyzer.connect()
                
                # Verifica proteções
                console.print("\n[yellow]2.1 Verificando proteções...[/yellow]")
                protections = analyzer.analyze_protections()
                
                for protection, status in protections.items():
                    symbol = "✓" if status else "✗"
                    color = "green" if status else "red"
                    console.print(f"[{color}]{symbol} {protection.upper()}: {status}[/{color}]")
                
                # Lista todos os imports primeiro
                console.print("\n[yellow]2.2 Listando imports...[/yellow]")
                imports = analyzer.r2.cmd("ii")  # Lista imports
                console.print("[cyan]Imports encontrados:[/cyan]")
                console.print(imports)
                
                # Lista funções
                console.print("\n[yellow]2.3 Listando funções...[/yellow]")
                functions = analyzer.r2.cmd("afl")  # Lista funções
                console.print("[cyan]Funções encontradas:[/cyan]")
                console.print(functions)
                
                # Procura vulnerabilidades
                console.print("\n[yellow]2.4 Procurando vulnerabilidades...[/yellow]")
                functions = analyzer.analyze_functions()
                vulns_found = []
                
                for func in functions:
                    if func.get('vulnerabilities'):
                        vulns_found.extend(func['vulnerabilities'])
                        console.print(f"[green]Vulnerabilidades em {func['name']}:[/green]")
                        for vuln in func['vulnerabilities']:
                            console.print(f"  • {vuln['type']}: {vuln['function']} - {vuln['reason']}")
                
                if not vulns_found:
                    console.print("[red]Nenhuma vulnerabilidade encontrada[/red]")
                    
                    # Vamos verificar manualmente
                    console.print("\n[yellow]Verificação manual de função main:[/yellow]")
                    main_addr = None
                    for func in functions:
                        if func['name'] == 'main':
                            main_addr = func['offset']
                            break
                    
                    if main_addr:
                        disasm = analyzer.r2.cmd(f'pdf @ {main_addr}')
                        console.print("[cyan]Disassembly da função main:[/cyan]")
                        console.print(disasm)
                        
                        # Procura por chamadas de função
                        if 'strcpy' in disasm:
                            console.print("[red]ENCONTRADO: chamada para strcpy no disassembly[/red]")
                        if 'printf' in disasm:
                            console.print("[yellow]ENCONTRADO: chamada para printf no disassembly[/yellow]")
                        if 'srand' in disasm or 'rand' in disasm:
                            console.print("[yellow]ENCONTRADO: uso de srand/rand no disassembly[/yellow]")
                
                analyzer.close()
                
            except Exception as e:
                console.print(f"[red]Erro durante análise: {str(e)}[/red]")
                console.print("[red]Detalhes do erro:[/red]")
                traceback.print_exc()
                return
            
            console.print("\n[bold green]Teste completado![/bold green]")
            
    except Exception as e:
        console.print(f"[red]Erro inesperado: {str(e)}[/red]")
        console.print("[red]Detalhes do erro:[/red]")
        traceback.print_exc()

if __name__ == "__main__":
    main()