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
