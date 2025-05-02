#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function() {
    char buffer[64];
    printf("Digite algo: ");
    gets(buffer);  // Vulnerável a buffer overflow
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