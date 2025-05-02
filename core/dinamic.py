import os
import docker
from utils.logging import get_logger

log = get_logger(__name__)
client = docker.from_env()

DEFAULT_IMAGE = "ghcr.io/reloadai/sandbox:latest"

def run_in_sandbox(path: str, timeout: int = 10) -> str:
    """Executa o binário isoladamente em contêiner e captura stdout."""
    abspath = os.path.abspath(path)
    if not os.path.exists(abspath):
        raise FileNotFoundError(f"Binário não encontrado: {abspath}")

    try:
        log.info(f"Executando {path} na sandbox Docker...")
        container = client.containers.run(
            DEFAULT_IMAGE,
            command=f"./{os.path.basename(path)}",
            volumes={os.path.dirname(abspath): {"bind": "/opt/bin", "mode": "ro"}},
            working_dir="/opt/bin",
            network_mode="none",
            detach=True,
            stdout=True,
            stderr=True,
            remove=True,
        )
        result = container.wait(timeout=timeout)
        logs = container.logs().decode("utf-8", errors="ignore")
        return logs

    except Exception as e:
        log.warning(f"Execução falhou: {e}")
        return "Erro ao executar em sandbox."

def setup_custom_unicorn_emulation(binary_path: str):
    """Stub para emulação com Unicorn (implementação futura)."""
    raise NotImplementedError("Unicorn emulation ainda não implementada.")
