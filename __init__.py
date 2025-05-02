"""
REloadAI - Automated binary analysis and exploit generation with AI
"""

__version__ = "2.0.0"

# CLI entrypoint
def cli_main():
    """Invoke the CLI entrypoint."""
    from .cli.reloadai_cli import main
    return main()

# Core engines
from .core.analyzer import BinaryAnalyzer
from .core.dynamic import DynamicAnalyzer
from .core.exploit_gen import ExploitGenerator
from .core.fingerprints import ssdeep_hash, imphash
from .core.packers import detect as detect_packer
from .core.cfg_visualizer import CFGVisualizer
from .core.binary_differ import BinaryDiffer
from .core.ctf_solver import CTFSolver
from .core.malware_generator import MalwareGenerator

__all__ = [
    "__version__",
    "cli_main",
    "BinaryAnalyzer",
    "DynamicAnalyzer",
    "ExploitGenerator",
    "ssdeep_hash",
    "imphash",
    "detect_packer",
    "CFGVisualizer",
    "BinaryDiffer",
    "CTFSolver",
    "MalwareGenerator",
]
