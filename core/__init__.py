"""
reloadai.core

Core analysis engines for REloadAI.
"""

# No import circular, apenas expõe versão caso definida no pacote raiz
try:
    from .. import __version__  # version definido em reloadai/__init__.py
except ImportError:
    __version__ = "0.0.0"

from .analyzer import BinaryAnalyzer, BinaryAnalysisError, SecurityError
from .dynamic import DynamicAnalyzer
from .exploit_gen import ExploitGenerator
from .bof_solver import BoFSolver
from .fingerprints import ssdeep_hash, imphash
from .packers import detect_packer
from .cfg_visualizer import CFGVisualizer
from .binary_differ import BinaryDiffer
from .ctf_solver import CTFSolver
from .malware_generator import MalwareGenerator

__all__ = [
    "__version__",
    "BinaryAnalyzer",
    "BinaryAnalysisError",
    "SecurityError",
    "DynamicAnalyzer",
    "ExploitGenerator",
    "BoFSolver",
    "ssdeep_hash",
    "imphash",
    "detect_packer",
    "CFGVisualizer",
    "BinaryDiffer",
    "CTFSolver",
    "MalwareGenerator",
]
