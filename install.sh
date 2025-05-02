#!/usr/bin/env bash
set -e

echo "🔧 Instalando dependências do sistema..."
sudo apt-get update && sudo apt-get install -y \
    python-venv \
    build-essential \
    libmagic-dev \
    binutils \
    radare2 \
    unzip \
    git \
    curl

if [ ! -d ".venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python -m venv .venv
fi

source .venv/bin/activate

echo "📚 Instalando dependências Python..."
pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt

echo "✅ Setup completo. Ative com: source .venv/bin/activate"
