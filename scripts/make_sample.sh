#!/bin/bash
# Gera binários simples de 32 e 64 bits para testes de BoF e análise estática

set -e

mkdir -p tests/samples

cat <<EOF > tests/samples/bof32.c
#include <stdio.h>
#include <string.h>

void vuln() {
    char buf[64];
    gets(buf);
    printf("Input: %s\n", buf);
}

int main() {
    vuln();
    return 0;
}
EOF

cat <<EOF > tests/samples/bof64.c
#include <stdio.h>
#include <string.h>

void vuln() {
    char buf[128];
    gets(buf);
    puts("Hello!");
}

int main() {
    vuln();
    return 0;
}
EOF

# Compila os binários com e sem proteções
gcc -m32 -no-pie -fno-stack-protector tests/samples/bof32.c -o tests/samples/bof32
gcc -m64 -no-pie -fno-stack-protector tests/samples/bof64.c -o tests/samples/bof64

echo "[✓] Binários de exemplo gerados em tests/samples/"
