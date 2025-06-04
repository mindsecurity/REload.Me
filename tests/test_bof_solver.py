import os
import pytest

try:
    from src.modules.exploit_development.bof_solver import (
        detect_bof_offset,
        suggest_payloads,
    )
except ModuleNotFoundError as e:
    pytest.skip(f"Required module not available: {e.name}", allow_module_level=True)


def test_bof_offset_and_payload():
    test_bin = os.path.join(os.path.dirname(__file__), "tests", "test_vulnerable")
    if not os.path.exists(test_bin):
        pytest.skip("Test binary not found")

    offset = detect_bof_offset(test_bin)
    assert offset is None or offset > 0

    if offset:
        payloads = suggest_payloads(offset, "amd64")
        assert "ret_only" in payloads
        assert "ret_shellcode" in payloads
        assert len(bytes.fromhex(payloads["ret_only"])) == offset + 8
