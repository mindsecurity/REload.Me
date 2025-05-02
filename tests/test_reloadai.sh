#!/bin/bash
# test_reloadai.sh - Script para testar o REloadAI (versão corrigida)

echo "=== Testando REloadAI ==="
echo

# 1. Criar diretório de testes
mkdir -p tests
cd tests

# 2. Criar e compilar binário de teste
cat > test_vulnerable.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Função alternativa para gets() que é vulnerável
char* dangerous_gets(char* buffer) {
    int c;
    char* dest = buffer;
    while ((c = getchar()) != '\n' && c != EOF) {
        *dest++ = c;
    }
    *dest = '\0';
    return buffer;
}

void vulnerable_function() {
    char buffer[64];
    printf("Digite algo: ");
    fflush(stdout);
    dangerous_gets(buffer);  // Vulnerável a buffer overflow
    printf("Você digitou: %s\n", buffer);
}

void unsafe_random() {
    srand(1234);  // Seed fixa - previsível
    int key = rand();
    printf("A chave secreta é: %d\n", key);
}

int main() {
    char password[16];
    
    printf("=== REloadAI Test Binary ===\n");
    
    // Teste de strcpy vulnerável
    strcpy(password, "FLAG{TEST123}");
    
    vulnerable_function();
    unsafe_random();
    
    return 0;
}
EOF

echo "Compilando binário de teste..."
gcc test_vulnerable.c -o test_vulnerable -fno-stack-protector -Wno-deprecated-declarations 

if [ $? -ne 0 ]; then
    echo "Erro: Falha ao compilar. Verifique se o GCC está instalado."
    exit 1
fi

# 3. Executar REloadAI
echo "Executando REloadAI..."
cd ..
python ../reloadai.py -f tests/test_vulnerable

# 4. Verificar arquivos gerados
echo
echo "Verificando arquivos gerados:"
if [ -f "REloadAI_output.md" ]; then
    echo "✓ REloadAI_output.md criado com sucesso"
    head -n 20 REloadAI_output.md
else
    echo "✗ REloadAI_output.md não foi criado"
fi

if [ -f "REloadAI_Aula.md" ]; then
    echo "✓ REloadAI_Aula.md criado com sucesso"
else
    echo "✗ REloadAI_Aula.md não foi criado"
fi

if [ -f "REloadAI_output.pdf" ]; then
    echo "✓ REloadAI_output.pdf criado com sucesso"
else
    echo "✗ REloadAI_output.pdf não foi criado"
fi

# 5. Verificar se exploit foi gerado (se houver)
if [ -f "exploit.c" ]; then
    echo "✓ exploit.c criado com sucesso"
    echo "Conteúdo do exploit:"
    cat exploit.c
else
    echo "✗ exploit.c não foi criado (pode não ser necessário)"
fi

echo
echo "=== Teste concluído ==="