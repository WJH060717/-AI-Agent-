import hashlib
import json
from pathlib import Path

from pydantic import Field

from packages.contracts.models import Contract

ROOT = Path(__file__).resolve().parents[2] / "knowledge/attack-18.1"


class KnowledgeError(ValueError):
    pass


class Strategy(Contract):
    object_id: str
    external_id: str
    url: str


class Entry(Contract):
    technique_id: str
    name: str = Field(max_length=150)
    object_id: str
    object_version: str
    modified: str
    source_url: str
    source_object_sha256: str
    platforms: list[str]
    rule_id: str
    applicable_observations: str = Field(max_length=250)
    normal_alternative: str = Field(max_length=250)
    detection_strategies: list[Strategy] = Field(max_length=3)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def identity(enabled: bool = True) -> str:
    if not enabled:
        return "disabled"
    # Includes invalid/missing identities too, so recovery cannot silently reuse earlier results.
    return sha(
        canonical(
            {
                n: sha((ROOT / n).read_bytes()) if (ROOT / n).is_file() else "missing"
                for n in ("manifest.json", "catalog.json", "freeze.json")
            }
        )
    )


class Catalog:
    def __init__(self, root: Path = ROOT):
        try:
            raw = (root / "catalog.json").read_bytes()
            freeze = json.loads((root / "freeze.json").read_bytes())
            if len(raw) > 40000 or sha(raw) != freeze["files"]["catalog.json"]:
                raise ValueError()
            document = json.loads(raw)
            self.version = document["knowledge_version"]
            self.digest = sha(raw)
            manifest_path = root / "manifest.json"
            self.manifest = (
                json.loads(manifest_path.read_bytes()) if manifest_path.is_file() else {}
            )
            if self.manifest and (
                self.manifest.get("catalog_sha256") != self.digest
                or self.manifest.get("knowledge_version") != self.version
            ):
                raise ValueError()
            values = [Entry.model_validate(item).model_dump() for item in document["entries"]]
            self.entries = {item["technique_id"]: item for item in values}
            if not 1 <= len(values) <= 50 or len(self.entries) != len(values):
                raise ValueError()
            self.unmapped_rules = sorted(self.manifest.get("unmapped_rules", []))
            self.rule_map = {
                rule: [item["technique_id"] for item in values if item["rule_id"] == rule]
                for rule in sorted({item["rule_id"] for item in values})
            }
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise KnowledgeError("KNOWLEDGE_INTEGRITY") from exc

    def lookup(self, ids: list[str]) -> list[dict]:
        if len(ids) > 5:
            raise KnowledgeError("KNOWLEDGE_LIMIT")
        return [
            self.entries[tid]
            | {
                "knowledge_version": self.version,
                "knowledge_ref": f"attack-18.1:{tid}:{self.digest}",
            }
            for tid in dict.fromkeys(ids)
            if tid in self.entries
        ]

    def for_rule(self, rule_id: str) -> list[dict]:
        return self.lookup(self.rule_map.get(rule_id, []))


def verify_sources(root: Path = ROOT) -> dict[str, int]:
    catalog = Catalog(root)
    freeze = json.loads((root / "freeze.json").read_bytes())
    for name in ("catalog.json", "source-objects.json", "LICENSE.txt", "source.json"):
        if sha((root / name).read_bytes()) != freeze["files"][name]:
            raise KnowledgeError("KNOWLEDGE_SOURCE_INTEGRITY")
    manifest_path = root / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_bytes())
        if manifest.get("catalog_sha256") != catalog.digest:
            raise KnowledgeError("KNOWLEDGE_MANIFEST_INTEGRITY")
    objects = {
        o["id"]: o for o in json.loads((root / "source-objects.json").read_bytes())["objects"]
    }
    for entry in catalog.entries.values():
        obj = objects[entry["object_id"]]
        if (
            sha(canonical(obj)) != entry["source_object_sha256"]
            or obj["name"] != entry["name"]
            or obj["x_mitre_version"] != entry["object_version"]
        ):
            raise KnowledgeError("KNOWLEDGE_SOURCE_MAPPING")
        for strategy in entry["detection_strategies"]:
            sid = strategy["object_id"]
            if not any(
                r.get("relationship_type") == "detects"
                and r["source_ref"] == sid
                and r["target_ref"] == obj["id"]
                for r in objects.values()
            ):
                raise KnowledgeError("KNOWLEDGE_SOURCE_MAPPING")
            for aid in objects[sid]["x_mitre_analytic_refs"]:
                for log in objects[aid].get("x_mitre_log_source_references", []):
                    if (
                        objects[log["x_mitre_data_component_ref"]]["type"]
                        != "x-mitre-data-component"
                    ):
                        raise KnowledgeError("KNOWLEDGE_SOURCE_MAPPING")
    return {
        label: sum(o["type"] == typ for o in objects.values())
        for label, typ in {
            "techniques": "attack-pattern",
            "strategies": "x-mitre-detection-strategy",
            "analytics": "x-mitre-analytic",
            "data_components": "x-mitre-data-component",
        }.items()
    }
