import base64

import pytest

from scripts.bro_protocol_sample import rows


def native(tmp_path, bad_uri=True, bad_port=False):
    source = tmp_path / "http.log"
    header = (
        b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        b"#fields\tuid\turi\tid.orig_p\n#types\tstring\tstring\tport\n"
    )
    uri = b"/x?A" + (b"\\xff%Q" if bad_uri else b"BCD")
    source.write_bytes(header + b"C1\t" + uri + b"\t" + (b"bad" if bad_port else b"123") + b"\n")
    return source


def test_native_bytes_are_reversible_and_old_default_still_rejects(tmp_path):
    source = native(tmp_path)
    rejected, restored = [], []
    assert rows(source, rejected=rejected) == [] and len(rejected) == 1
    items = rows(source, binary_fields={"uri"}, restored=restored)
    assert len(items) == 1 and "uri" not in items[0]["record"]
    assert base64.b64decode(items[0]["record"]["uri_b64"]) == b"/x?A" + bytes([255]) + b"%Q"
    assert restored[0]["fields"] == ["uri"] and restored[0]["source_line"] == 7
    assert items[0]["source_line_sha256"] == restored[0]["source_line_sha256"]


def test_other_invalid_fields_still_reject_and_wrapper_fields_are_fixed(tmp_path):
    rejected = []
    assert rows(native(tmp_path, bad_port=True), binary_fields={"uri"}, rejected=rejected) == []
    assert len(rejected) == 1
    with pytest.raises(ValueError):
        rows(native(tmp_path), binary_fields={"uid"})


def test_third_round_sampler_keeps_wrapper_not_label(tmp_path):
    import json

    from eval.ctu13_cc_round3 import write_sample

    source = native(tmp_path)
    restored = []
    selected = rows(source, binary_fields={"uri"}, restored=restored)
    selected[0]["record"]["Label"] = "From-Botnet"
    output = tmp_path / "sample"
    write_sample(output, {"zeek_http": source}, {"zeek_http": selected})
    value = json.loads((output / "zeek_http.jsonl").read_bytes())
    assert "uri_b64" in value and "Label" not in value
