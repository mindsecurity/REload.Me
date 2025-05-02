import os
from reloadai.core.analyzer import analyze_static

def test_analyze_static_basic():
    path = os.path.join(os.path.dirname(__file__), "samples", "mini64")
    result = analyze_static(path)

    assert isinstance(result["functions"], list)
    assert result["arch"] == "x86" or result["arch"] == "amd64"
    assert result["main_disasm"]
    assert result["cfg"]
