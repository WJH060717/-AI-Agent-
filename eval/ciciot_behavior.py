"""Score Section 13.9 behavior separately from historical exact classification."""

import argparse
import json
from collections import Counter
from pathlib import Path

from eval.ciciot_extension import EXTENSION_MANIFESTS, run
from scripts.verify_fragment_rules import sha256_bytes

FIXED_VERSION = "ciciot-extension@1.1.0"
METHOD = "ciciot-behavior@1.0.0"
# Register against the original fixed roles. Supplemental and synthetic inputs
# must not fill a missing fixed row.
EXPECTED = {
    "Recon-PortScan": ("port_scan", "R24", "1.0.0"),
    "Recon-HostDiscovery": ("host_discovery_suspected", "R26", "1.1.0"),
    "Recon-OSScan": ("os_fingerprint_probe", "R30", "1.0.0"),
    "VulnerabilityScan": ("vulnerability_scan_suspected", None, None),
    "Mirai-greip_flood": ("gre_ip_flood", "R27", "1.0.0"),
    "Mirai-greeth_flood": ("gre_ethernet_flood", "R27", "1.0.0"),
    "Mirai-udpplain": ("direct_udp_flood", "R20", "1.3.0"),
    "DNS_Spoofing": ("dns_spoofing_suspected", "R29", "1.0.0"),
    "MITM-ArpSpoofing": ("arp_spoofing_suspected", "R28", "1.0.0"),
    "DictionaryBruteForce": ("brute_force_suspected", "R02", "1.0.0"),
    "Backdoor_Malware": ("backdoor_suspected", None, None),
    "BrowserHijacking": ("browser_hijack_suspected", None, None),
    "CommandInjection": ("command_injection_attempt", None, None),
    "SqlInjection": ("sql_injection_attempt", None, None),
    "Uploading_Attack": ("suspicious_upload", None, None),
    "XSS": ("xss_attempt", None, None),
}
NO_SCORE = {"failed", "collection_failed", "unverified"}
type Signature = tuple[str, str | None, str | None]


def observations(case: dict) -> list[dict]:
    return [
        item | {"report_verified": candidate.get("behavior_report_verified", False)}
        for key in ("verified_candidates", "unclassified_candidates")
        for candidate in case.get(key, [])
        for item in candidate.get("behavior_assessments", [])
    ]


def signature(item: dict) -> Signature:
    return item["behavior"], item["rule_id"], item["rule_version"]


def grade(
    case: dict, expected: Signature, controls_ready: bool, control_hits: set[Signature]
) -> dict:
    observed = observations(case)
    status = case["status"]
    if status not in NO_SCORE:
        matches = [item for item in observed if signature(item) == expected]
        if not matches:
            status = "behavior_not_detected"
        elif not all(item["report_verified"] for item in matches):
            status = "behavior_report_unverified"
        elif not controls_ready or expected in control_hits:
            status = "behavior_control_unresolved"
        else:
            status = "behavior_pass"
    return {"status": status, "observed": observed}


def score(extended: dict) -> dict:
    if extended["manifest_sha256"] != EXTENSION_MANIFESTS[FIXED_VERSION]:
        raise ValueError("unexpected fixed manifest")
    controls = extended["normal_controls"]
    control_observations = [item for case in controls["rows"] for item in observations(case)]
    controls_ready = controls["captures_run"] == controls["captures_expected"] > 0 and all(
        item["report_verified"] for item in control_observations
    )
    control_hits = {signature(item) for item in control_observations}
    rows = []
    by_subtype = {row["subtype"]: row for row in extended["rows"]}
    if len(extended["rows"]) != 17 or set(by_subtype) != EXPECTED.keys() | {"Recon-PingSweep"}:
        raise ValueError("behavior task denominator changed")
    for subtype, expected in EXPECTED.items():
        row = by_subtype[subtype]
        behavior, rule, version = expected
        rows.append(
            {
                "subtype": subtype,
                "expected": {"behavior": behavior, "rule_id": rule, "rule_version": version},
                "fixed": grade(row["fixed"], expected, controls_ready, control_hits),
                "supplements": [
                    grade(item, expected, controls_ready, control_hits)
                    for item in row["supplements"]
                ],
                "exact_scoring_status": row["fixed"]["status"],
                "prior_evidence_gap": row["missing_evidence"],
            }
        )
    counts = Counter(row["fixed"]["status"] for row in rows)
    return {
        "method": METHOD,
        "fixed_manifest_sha256": extended["manifest_sha256"],
        "method_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "fixed_total": len(rows),
        "fixed_passed": counts["behavior_pass"],
        "fixed_counts": dict(counts),
        "supplement_rows_passed": sum(
            any(item["status"] == "behavior_pass" for item in row["supplements"]) for row in rows
        ),
        "controls_verified": controls_ready,
        "control_hits": [list(key) for key in sorted(control_hits)],
        "ping_sweep_exact_regression": by_subtype["Recon-PingSweep"]["fixed"]["status"],
        "rows": rows,
        "inspection": extended,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    if args.result.exists():
        parser.error("result path already exists")
    result = score(run(Path("eval/configs/ciciot-extension-02.json"), normal_controls=True))
    args.result.parent.mkdir(parents=True, exist_ok=True)
    with args.result.open("x", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
        output.write("\n")
    return 0 if result["fixed_passed"] == result["fixed_total"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
