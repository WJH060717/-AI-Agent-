import pytest


def test_protocol_adapter_vectors_types_and_provenance(tmp_path):
    from scripts.bro_protocol_sample import rows

    raw = (
        b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        b"#fields\tts\tuid\tanswers\trejected\n#types\ttime\tstring\tvector[string]\tbool\n"
        b"1.25\tC1\t192.0.2.1,alias\\x2eexample\tF\n"
    )
    path = tmp_path / "dns.log"
    path.write_bytes(raw)
    records = rows(path)
    assert records[0]["record"] == {
        "ts": 1.25,
        "uid": "C1",
        "answers": ["192.0.2.1", "alias.example"],
        "rejected": False,
    }
    assert records[0]["source_line"] == 7
    assert len(records[0]["source_line_sha256"]) == 64
    path.write_bytes(raw[:-1])
    with pytest.raises(ValueError, match="incomplete"):
        rows(path)


def test_invalid_source_bytes_are_recorded_without_guessing_encoding(tmp_path):
    from scripts.bro_protocol_sample import rows

    path = tmp_path / "http.log"
    path.write_bytes(
        b"#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n"
        b"#unset_field\t-\n#fields\tuid\turi\n#types\tstring\tstring\n"
        b"C1\t/ok.exe\nC2\t/\\xe1.exe\n"
    )
    rejected = []
    result = rows(path, rejected=rejected)
    assert len(result) == len(rejected) == 1
    assert rejected[0]["source_line"] == 8 and rejected[0]["uid"] == "C2"
