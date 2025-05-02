FROM python:3.11-slim

# Instala dependências de sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    radare2 \
    binutils \
    curl \
    unzip \
    python3-dev \
    python3-pip \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Cria diretório de trabalho
WORKDIR /app

# Copia dependências
COPY requirements.txt requirements-dev.txt ./

# Instala dependências
RUN pip install --upgrade pip \
    && pip install -r requirements.txt -r requirements-dev.txt

# Copia o restante do código
COPY . .

# Entrypoint padrão
CMD ["python3", "-m", "reloadai.cli.reloadai_cli"]
