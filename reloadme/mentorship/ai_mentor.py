from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional
from pathlib import Path

from rich import print as rprint


class AIMentor:
    def __init__(self, analysis_data: Dict[str, Any], api_key: Optional[str] = None):
        self.analysis_data = analysis_data
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or self._load_api_key_from_file()
        if not self.api_key:
            rprint("[bold yellow]Aviso: OPENAI_API_KEY não definido e arquivo .r2ai.openai-key não encontrado.[/bold yellow]")
            rprint("Prosseguindo sem mentoria de IA.")

    def _load_api_key_from_file(self) -> Optional[str]:
        candidates = [
            Path.cwd() / ".r2ai.openai-key",
            Path.home() / ".r2ai.openai-key",
        ]
        for p in candidates:
            try:
                if p.is_file():
                    key = p.read_text(encoding="utf-8").strip()
                    if key:
                        return key.splitlines()[0].strip()
            except Exception:
                continue
        return None

    def _build_prompt(self) -> str:
        formatted = json.dumps(self.analysis_data, ensure_ascii=False, indent=2)
        template = (
            "Você é um Engenheiro Reverso Sênior e Analista de Malware de classe mundial, com foco em ser um mentor. "
            "Sua missão é analisar os dados estáticos de um binário que eu forneci e me guiar nos próximos passos. "
            "Seja didático, claro e direto.\n\n"
            "**Dados do Binário:**\n---\n"
            f"{formatted}\n"
            "---\n\n"
            "**Sua Tarefa:**\n"
            "Com base **exclusivamente** nos dados fornecidos, responda às seguintes perguntas em formato Markdown:\n\n"
            "1. **Resumo da Hipótese Inicial:** Qual é a provável função deste binário? "
            "É uma ferramenta de sistema, um malware, um downloader? Justifique com base nos imports (ex: `CreateFileW`, `WriteProcessMemory`, `socket`) e strings encontradas.\n\n"
            "2. **Pontos de Atenção (Red Flags):** Existem indicadores de ofuscação, técnicas de anti-análise ou funcionalidades maliciosas? "
            "(ex: imports como `IsDebuggerPresent`, strings com nomes de AV, alta entropia em seções).\n\n"
            "3. **Funções-Chave para Iniciar a Análise:** Quais 3-5 funções (incluindo a 'main' ou 'entrypoint') eu deveria investigar primeiro na análise dinâmica? "
            "Forneça o nome e o endereço de cada uma.\n\n"
            "4. **Plano Sugerido para Análise Dinâmica:** Me dê um plano de ação claro.\n"
            "   * Exemplo 1: \"Comece colocando um breakpoint em `0x401550` (função `malicious_setup`). Observe os argumentos passados para `CreateRemoteThread` para ver qual código ele está injetando.\"\n"
            "   * Exemplo 2: \"Foque na função `download_payload` em `0x4016a0`. Monitore o tráfego de rede com o Wireshark quando essa função for chamada para descobrir o endereço do servidor C2.\"\n"
        )
        return template

    def get_mentorship(self) -> Optional[str]:
        if not self.api_key:
            return None

        prompt = self._build_prompt()

        # Lazy import to avoid hard dependency when not used
        try:
            # Support both new and legacy SDK usage patterns
            try:
                from openai import OpenAI  # type: ignore

                client = OpenAI(api_key=self.api_key)
                # Use responses API if available, fallback to chat
                try:
                    resp = client.chat.completions.create(
                        model="gpt-4o-mini",
                        messages=[
                            {"role": "system", "content": "Você é um mentor sênior de engenharia reversa."},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        max_tokens=900,
                    )
                    return resp.choices[0].message.content  # type: ignore
                except Exception:
                    pass
            except Exception:
                pass

            # Legacy SDK fallback
            import openai  # type: ignore

            openai.api_key = self.api_key
            resp = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Você é um mentor sênior de engenharia reversa."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=900,
            )
            return resp["choices"][0]["message"]["content"]
        except Exception:
            return None
