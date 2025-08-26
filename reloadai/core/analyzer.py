"""Compatibility wrapper for static analysis utilities."""
from src.modules.static_analysis.static_analyzer import (
    BinaryAnalyzer,
    BinaryAnalysisError,
    SecurityError,
)


def analyze_static(binary_path: str, deep: bool = False, openai_key: str = "") -> dict:
    """Run a radare2-based static analysis on ``binary_path``.

    Parameters
    ----------
    binary_path: str
        Path to the binary to inspect.
    deep: bool
        Enable a deeper ``aaa`` analysis in radare2.
    openai_key: str
        API key for optional GPT-assisted features.
    """
    analyzer = BinaryAnalyzer(binary_path, openai_key)
    try:
        return analyzer.analyze_static_details(deep=deep)
    finally:
        analyzer.close()


__all__ = [
    "analyze_static",
    "BinaryAnalyzer",
    "BinaryAnalysisError",
    "SecurityError",
]
