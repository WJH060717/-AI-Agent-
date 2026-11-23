import json


def test_sampler_preserves_user_agent_only_in_raw_and_filters_labels(tmp_path):
    from eval.ctu13_cc_round2 import write_sample

    original = tmp_path / "http.log"
    original.write_bytes(b"original\n")
    selected = {
        "zeek_http": [
            {
                "source_line": 1,
                "source_line_sha256": "a" * 64,
                "record": {
                    "ts": 1,
                    "uid": "C1",
                    "user_agent": "Client/1",
                    "uri": "/x",
                    "Label": "From-Botnet",
                    "answer": "forbidden",
                },
            }
        ]
    }
    output = tmp_path / "sample"
    write_sample(output, {"zeek_http": original}, selected)
    record = json.loads((output / "zeek_http.jsonl").read_bytes())
    assert record["user_agent"] == "Client/1"
    assert "Label" not in record and "answer" not in record
