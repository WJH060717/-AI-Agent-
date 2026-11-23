"""Select pinned public ATT&CK objects offline; no runtime downloading or evaluation input."""

import argparse
import hashlib
import json
from pathlib import Path

COMMIT = "b4eb2b84c02b84bb4cceb71c97ae05cb2f33ab38"
SOURCE_SHA = "f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb"
NOTES = {
    "T1046": (
        "R01",
        "同源短窗多目标或多端口连接，可辅助定位扫描候选。",
        "资产巡检、可用性检测也可能产生相似连接。",
    ),
    "T1110": (
        "R02",
        "同账号或来源的重复认证失败及后续结果，需保留主机与时间范围。",
        "密码过期、服务配置错误或用户误输也可造成失败。",
    ),
    "T1059.004": (
        "R03",
        "Unix shell 执行记录须结合可靠进程身份、父子关系与原始片段。",
        "授权运维和自动化脚本也会调用 shell。",
    ),
    "T1021.004": (
        "R04",
        "SSH 认证与连接可提供资产级访问候选；缺 socket 不建立进程归属。",
        "合法远程管理也会产生 SSH 访问；候选不证明成功横向移动。",
    ),
    "T1071": (
        "R05",
        "周期性连接只提供应用层通信候选，需要协议与其他证据补证。",
        "监控心跳、健康检查同样周期通信；周期本身不证明 C2。",
    ),
    "T1041": (
        "R06",
        "基于预先冻结正常上下文的出站流量偏离可提示调查方向。",
        "备份、同步、更新也可能产生大流量；异常量不证明数据窃取。",
    ),
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def build(source: Path, destination: Path) -> None:
    raw = (source / "enterprise-attack-18.1.json").read_bytes()
    if sha(raw) != SOURCE_SHA:
        raise ValueError("PINNED_SOURCE_MISMATCH")
    download = json.loads((source / "download.json").read_text(encoding="utf8"))
    if download["commit"] != COMMIT:
        raise ValueError("PINNED_COMMIT_MISMATCH")
    objects = {o["id"]: o for o in json.loads(raw)["objects"]}
    selected, entries = {}, []
    for obj in objects.values():
        refs = [
            r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"
        ]
        if obj["type"] != "attack-pattern" or not refs or refs[0].get("external_id") not in NOTES:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = refs[0]
        tid = ref["external_id"]
        rule, observations, alternative = NOTES[tid]
        strategies = []
        selected[obj["id"]] = obj
        for relation in objects.values():
            if (
                relation["type"] != "relationship"
                or relation.get("relationship_type") != "detects"
                or relation["target_ref"] != obj["id"]
            ):
                continue
            strategy = objects[relation["source_ref"]]
            if (
                strategy["type"] != "x-mitre-detection-strategy"
                or strategy.get("x_mitre_deprecated")
                or relation.get("revoked")
            ):
                continue
            selected[relation["id"]] = relation
            selected[strategy["id"]] = strategy
            sref = next(
                r for r in strategy["external_references"] if r["source_name"] == "mitre-attack"
            )
            strategies.append(
                {
                    "object_id": strategy["id"],
                    "external_id": sref["external_id"],
                    "url": sref["url"],
                }
            )
            for aid in strategy["x_mitre_analytic_refs"]:
                analytic = objects[aid]
                selected[aid] = analytic
                for log in analytic.get("x_mitre_log_source_references", []):
                    cid = log["x_mitre_data_component_ref"]
                    selected[cid] = objects[cid]
        entry = {
            "technique_id": tid,
            "name": obj["name"],
            "object_id": obj["id"],
            "object_version": obj["x_mitre_version"],
            "modified": obj["modified"],
            "source_url": ref["url"],
            "source_object_sha256": sha(canonical(obj)),
            "platforms": obj.get("x_mitre_platforms", []),
            "rule_id": rule,
            "applicable_observations": observations,
            "normal_alternative": alternative,
            "detection_strategies": strategies,
        }
        entries.append(entry)
    if len(entries) != 6:
        raise ValueError("INCOMPLETE_CURATED_SET")
    destination.mkdir(exist_ok=False)
    catalog = {
        "knowledge_version": "attack-18.1-curated@1.0.0",
        "entries": sorted(entries, key=lambda x: x["technique_id"]),
    }
    files = {
        "catalog.json": canonical(catalog),
        "source-objects.json": canonical(
            {"objects": sorted(selected.values(), key=lambda x: x["id"])}
        ),
        "LICENSE.txt": (source / "LICENSE.txt").read_bytes(),
        "source.json": canonical(download),
    }
    for name, content in files.items():
        (destination / name).write_bytes(content)
    (destination / "freeze.json").write_bytes(
        canonical(
            {"version": "knowledge-freeze@1.0.0", "files": {k: sha(v) for k, v in files.items()}}
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.source, args.output)
