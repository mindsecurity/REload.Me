from reloadai.core.bof_solver import detect_bof_offset, suggest_payloads

def test_bof_offset_and_payload():
    offset = detect_bof_offset("tests/samples/mini64")
    assert offset is None or offset > 0

    if offset:
        payloads = suggest_payloads(offset, "amd64")
        assert "ret_only" in payloads
        assert "ret_shellcode" in payloads
