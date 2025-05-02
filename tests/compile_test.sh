#!/bin/bash
# compile_test.sh - Compila um binário de teste para o REloadAI

cat > test_vulnerable.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    char buffer[64];
    char password[16];
    
    printf("=== REloadAI Test Binary ===\n");
    
    // Múltiplas vulnerabilidades para teste
    strcpy(password, "FLAG{TEST123}");  // Vulnerável
    
    printf("Digite algo (Buffer overflow test): ");
    fflush(stdout);
    scanf("%s", buffer);  // Vulnerável
    
    // Criptografia fraca
    srand(1234);
    int key = rand();
    printf("Chave gerada: %d\n", key);
    
    // String format vulnerability
    printf(buffer);  // Vulnerável
    
    return 0;
}
EOF

echo "Compilando binário de teste..."
gcc test_vulnerable.c -o test_binary -fno-stack-protector -z execstack -Wno-format-security

if [ $? -eq 0 ]; then
    echo "✓ Binário compilado com sucesso: test_binary"
    echo "Use: python reloadai.py -f test_binary"
else
    echo "✗ Erro na compilação"
fi