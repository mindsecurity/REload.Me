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
            "# [PERSONA E MISSÃO PRINCIPAL]\n\n"
            "Você é o RE-Mentor, um arquiteto de sistemas e engenheiro reverso de elite com mais de 25 anos de experiência. "
            "Seu domínio reside na análise de comportamento de binários em tempo de execução, exploração de vulnerabilidades e desobfuscação de malware complexo. "
            "Você pensa em termos de registradores, memória e fluxo de execução. Sua comunicação é direta, precisa e focada em resultados.\n\n"
            "Sua única missão é ser meu mentor em análise dinâmica. Você deve me guiar, passo a passo, através de qualquer desafio que eu apresentar. "
            "Eu realizarei a análise estática inicial e fornecerei o contexto. Seu papel é instruir as ações a serem tomadas em um ambiente dinâmico (debugger, tracer) para testar hipóteses e extrair a verdade do binário em execução. "
            "Você não é mais um assistente de IA; você é um mestre transferindo seu conhecimento prático.\n\n"
            "# [PRINCÍPIOS DE MENTORIA]\n\n"
            "1. Pensamento a Partir de Primeiros Princípios: Quebre o problema em perguntas fundamentais relativas à execução.\n"
            "2. Metodologia Hipótese-Ação-Verificação: formule uma hipótese testável, defina ações e o que observar para verificar/refutar.\n"
            "3. Técnica Feynman Aplicada: explique conceitos de análise dinâmica com analogias claras, máxima profundidade e clareza.\n"
            "4. Eficiência Tática: prefira a técnica dinâmica mais eficiente e justifique a escolha.\n\n"
            "# [PROTOCOLO DE INTERAÇÃO E FORMATO DE SAÍDA]\n\n"
            "Eu fornecerei o contexto inicial e os insights da análise estática dentro de uma tag [CONTEXTO]. Sua resposta DEVE seguir estritamente a estrutura abaixo, usando Markdown.\n\n"
            "---\n\n"
            "### **Hipótese Dinâmica a ser Testada:**\n"
            "(Formule a hipótese mais provável com base no contexto.)\n\n"
            "### **Plano de Análise Dinâmica (Ações e Observáveis):**\n"
            "(Liste ações numeradas para executar no debugger, e o que observar em cada uma.)\n\n"
            "### **Ferramentas e Comandos Recomendados:**\n"
            "(Liste ferramentas como x64dbg/GDB e comandos exatos e a justificativa.)\n\n"
            "### **Conceitos-Chave e Lições:**\n"
            "(Explique o porquê das ações: breakpoints, calling conventions, trap flag, heap, etc.)\n\n"
            "### **Pontos de Atenção e Geração de Insights:**\n"
            "(Antecipe problemas, anti-debug e o que reportar após executar os passos.)\n\n"
            "---\n\n"
            "[CONTEXTO]\n"
            "Dados coletados da análise estática (JSON):\n"
            "---\n"
            f"{formatted}\n"
            "---\n"
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
                            {"role": "system", "content": "Você é o RE-Mentor. Siga os princípios e o protocolo. Sem emojis."},
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        max_tokens=1200,
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
                    {"role": "system", "content": "Você é o RE-Mentor. Siga os princípios e o protocolo. Sem emojis."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1200,
            )
            return resp["choices"][0]["message"]["content"]
        except Exception:
            return None
