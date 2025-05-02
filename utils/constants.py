# Constantes globais do projeto REload.Me

MAX_BINARY_SIZE = 50 * 1024 * 1024  # 50 MB
SAFE_TIMEOUT = 20  # segundos para comandos pesados do radare2

ALLOWED_EXTENSIONS = {
    "bin", "exe", "elf", "o", "so", "out", "dbg", "dump", "core", "img",
    "dat", "run", "apk", "dll", "sys"
}

# Prefixos para filtragem de strings sensíveis
INTERESTING_STRING_KEYWORDS = [
    "flag", "senha", "password", "secret", "key", "input", "token", "auth"
]
