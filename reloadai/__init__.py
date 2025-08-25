"""REloadAI - Automated binary analysis and exploit generation with AI"""

__version__ = "2.0.0"

def cli_main():
    """Invoke the CLI entrypoint."""
    from cli.reloadai_cli import main
    return main()

from src.modules.static_analysis.static_analyzer import (
    BinaryAnalyzer,
    BinaryAnalysisError,
    SecurityError,
)

try:  # Optional heavy dependencies
    from src.modules.dynamic_analysis.dynamic_analyzer import DynamicAnalyzer
except Exception:  # pragma: no cover - optional
    DynamicAnalyzer = None

try:
    from src.modules.exploit_development.exploit_generator import ExploitGenerator
except Exception:  # pragma: no cover - optional
    ExploitGenerator = None

try:
    from core.fingerprints import ssdeep_hash, imphash
    from core.packers import detect as detect_packer
    from core.cfg_visualizer import CFGVisualizer
    from core.binary_differ import BinaryDiffer
    from core.ctf_solver import CTFSolver
    from core.malware_generator import MalwareGenerator
except Exception:  # pragma: no cover - optional
    ssdeep_hash = imphash = detect_packer = CFGVisualizer = None
    BinaryDiffer = CTFSolver = MalwareGenerator = None

__all__ = [
    "__version__",
    "cli_main",
    "BinaryAnalyzer",
    "BinaryAnalysisError",
    "SecurityError",
]
if DynamicAnalyzer:
    __all__.append("DynamicAnalyzer")
if ExploitGenerator:
    __all__.append("ExploitGenerator")
if ssdeep_hash:
    __all__.extend([
        "ssdeep_hash",
        "imphash",
        "detect_packer",
        "CFGVisualizer",
        "BinaryDiffer",
        "CTFSolver",
        "MalwareGenerator",
    ])
