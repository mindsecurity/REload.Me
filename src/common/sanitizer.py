import os, hashlib, magic   # python-magic
from config import Config

class BinarySanitizer:
    """Valida caminho, extensão, tamanho, MIME e devolve metadados seguros."""

    @staticmethod
    def sanitize(path: str) -> dict:
        abs_path = os.path.abspath(path)

        # ── 1. existência e tipo ────────────────────────────────────────────────
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Arquivo {abs_path} não encontrado")
        if not os.path.isfile(abs_path):
            raise ValueError(f"{abs_path} não é arquivo regular")

        # ── 2. extensão whitelist ───────────────────────────────────────────────
        ext = os.path.splitext(abs_path)[1].lstrip(".").lower()
        if ext == "":                      
            pass
        elif ext not in Config.ALLOWED_EXTENSIONS:
            raise ValueError(f"Extensão .{ext} não permitida")

        # ── 3. tamanho máximo ───────────────────────────────────────────────────
        size = os.path.getsize(abs_path)
        if size > Config.MAX_BINARY_SIZE:
            raise ValueError(
                f"Tamanho {size/1024/1024:.1f} MB excede limite "
                f"de {Config.MAX_BINARY_SIZE/1024/1024} MB"
            )

        # ── 4. tipo MIME coerente ──────────────────────────────────────────────
        mime = magic.from_file(abs_path, mime=True)
        if not mime.startswith(("application/x", "application/octet-stream")):
            raise ValueError(f"MIME não suportado: {mime}")

        # ── 5. hash para catalogação/log ───────────────────────────────────────
        with open(abs_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        return {
            "path": abs_path,
            "name": os.path.basename(abs_path),
            "size": size,
            "mime": mime,
            "sha256": sha256,
            "extension": ext,
        }
