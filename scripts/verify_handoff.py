"""Exercise only a newly initialized handoff instance; credentials never leave local memory."""

import argparse
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import httpx

from scripts.verify_ctu13 import pages, save, wait_terminal


def check(bundle: Path, output: Path, previous: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    state = json.loads((bundle / "_local/state.json").read_bytes())
    access = json.loads((bundle / "_local/access.json").read_bytes())
    initialized = json.loads((bundle / "_local/initialized.json").read_bytes())
    if not state["project"].startswith("tracehandoff") or not 1024 <= state["port"] <= 65535:
        raise ValueError("not a handoff instance")
    token = access["tokens"]["admin"]
    result = {
        "project": state["project"],
        "port": state["port"],
        "token_digest": hashlib.sha256(token.encode()).hexdigest(),
        "models": 0,
        "reports": [],
    }
    with httpx.Client(
        base_url=f"http://127.0.0.1:{state['port']}/api/v1",
        headers={"Authorization": "Bearer " + token},
        trust_env=False,
        timeout=90,
    ) as client:
        batch = wait_terminal(client, f"/imports/{initialized['batch_id']}", "status")
        assert batch["status"] == "succeeded" and batch["accepted"] == 24
        datasets = pages(client, "/datasets")
        seed = next(d for d in datasets if d["dataset_id"] == initialized["dataset_id"])
        scope = {"dataset_id": seed["dataset_id"], "session_id": seed["default_session_id"]}
        assert len(pages(client, "/events", scope)) == 24
        if previous:
            before = json.loads(previous.read_bytes())
            assert result["token_digest"] == before["token_digest"]
            for report_id in before["reports"]:
                response = client.get(f"/reports/{report_id}")
                response.raise_for_status()
                assert response.json()["validation"] == "passed"
            assert len(pages(client, "/events", before["ctu_scope"])) == 207
            result.update(
                restart_preserved=True, reports=before["reports"], ctu_scope=before["ctu_scope"]
            )
        else:
            response = client.post(
                "/datasets",
                headers={"Idempotency-Key": str(uuid4())},
                json={"name": "CTU-13 handoff verification", "provenance_type": "derived"},
            )
            response.raise_for_status()
            dataset = response.json()
            ctu_scope = {
                "dataset_id": dataset["dataset_id"],
                "session_id": dataset["default_session_id"],
            }
            sample = bundle / "project/artifacts/cc-round4-01/samples-01/cc-only"
            imports = []
            for source in ("zeek", "zeek_http", "pcap", "pcap_http"):
                raw = (sample / (source + ".jsonl")).read_bytes()
                count = len(raw.splitlines())
                for repeat in range(2):
                    response = client.post(
                        "/imports",
                        headers={"Idempotency-Key": str(uuid4())},
                        data={
                            "dataset_id": dataset["dataset_id"],
                            "source_type": source,
                            "sensor_id": "ctu13-s07-pcap"
                            if source.startswith("pcap")
                            else "ctu13-s07-bro",
                            "timezone": "UTC",
                        },
                        files={"file": (source + ".jsonl", raw, "application/json")},
                    )
                    response.raise_for_status()
                    status = wait_terminal(
                        client, f"/imports/{response.json()['batch_id']}", "status"
                    )
                    assert status["status"] == "succeeded" and status["quarantined"] == 0
                    assert status["accepted"] == (0 if repeat else count)
                    assert status["duplicate"] == (count if repeat else 0)
                    imports.append(status)
            assert len(pages(client, "/events", ctu_scope)) == 207
            incidents = pages(client, "/incidents", scope) + pages(client, "/incidents", ctu_scope)
            assert len(incidents) == 4
            for incident in incidents:
                response = client.post(
                    f"/incidents/{incident['id']}/investigations",
                    headers={"Idempotency-Key": str(uuid4())},
                    json={"mode": "deterministic"},
                )
                response.raise_for_status()
                run = wait_terminal(client, f"/investigations/{response.json()['run_id']}", "state")
                assert run["state"] == "completed" and run["budget_used"]["model_calls"] == 0
                response = client.get(f"/reports/{run['report_id']}")
                response.raise_for_status()
                report = response.json()
                assert (
                    report["validation"] == "passed" and report["mode"] == "deterministic_fallback"
                )
                for event_id in report["timeline"]:
                    response = client.get(
                        f"/evidence/{event_id}", params={"snapshot_id": run["snapshot_id"]}
                    )
                    response.raise_for_status()
                    evidence = response.json()
                    assert evidence["verified"] and evidence["redacted"]
                    assert "request_b64" not in json.dumps(
                        evidence
                    ) and "response_b64" not in json.dumps(evidence)
                for format in ("html", "json"):
                    response = client.get(
                        f"/reports/{run['report_id']}/export", params={"format": format}
                    )
                    response.raise_for_status()
                    (output / (run["report_id"] + "." + format)).write_bytes(response.content)
                result["reports"].append(run["report_id"])
            save(output / "imports.json", imports)
            result.update(
                seed_events=24,
                ctu_events=207,
                ctu_scope=ctu_scope,
                report_count=len(result["reports"]),
                source_types=4,
                dedup_verified=True,
            )
    result["status"] = "passed"
    save(output / "result.json", result)
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in {"token_digest", "ctu_scope", "reports"}}
        )
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    check(args.bundle.resolve(), args.output.resolve(), args.previous)
