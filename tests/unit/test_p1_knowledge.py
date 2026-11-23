import json

import pytest

from packages.agent.validation import DraftError, validate_draft
from packages.config import Settings
from packages.contracts.agent import ReportDraft


def test_catalog_has_sourced_six_rules_and_fails_closed_on_tamper(tmp_path):
    from packages.knowledge.catalog import ROOT, Catalog, KnowledgeError

    catalog = Catalog()
    items = catalog.lookup(["T1110", "T1110", "T9999", "T1059.004"])
    assert [x["technique_id"] for x in items] == ["T1110", "T1059.004"]
    assert all(x["knowledge_ref"].startswith("attack-18.1:") for x in items)
    assert all(x["source_url"].startswith("https://attack.mitre.org/") for x in items)
    assert all(x["source_object_sha256"] and x["detection_strategies"] for x in items)
    assert not any("event_id" in x for x in items)
    assert len(json.dumps(catalog.lookup(list(catalog.entries)[:5])).encode()) < 13000
    for name in ["catalog.json", "freeze.json"]:
        (tmp_path / name).write_bytes((ROOT / name).read_bytes())
    doc = json.loads((tmp_path / "catalog.json").read_text(encoding="utf8"))
    doc["entries"][0]["name"] = "altered"
    (tmp_path / "catalog.json").write_text(json.dumps(doc), encoding="utf8")
    with pytest.raises(KnowledgeError, match="KNOWLEDGE_INTEGRITY"):
        Catalog(tmp_path)


def test_knowledge_reference_requires_completed_tool_and_never_proves_fact():
    from packages.knowledge.catalog import Catalog

    ref = Catalog().lookup(["T1110"])[0]["knowledge_ref"]
    draft = ReportDraft.model_validate({"claims": [{"kind": "unknown", "knowledge_refs": [ref]}]})
    with pytest.raises(DraftError, match="KNOWLEDGE_REFERENCE"):
        validate_draft(draft, [], set(), [], None)
    claims = validate_draft(draft, [], set(), [], None, {ref})
    assert claims[0].knowledge_refs == [ref] and claims[0].kind == "unknown"
    draft.claims[0].kind = "observed"
    with pytest.raises(DraftError, match="WITHOUT_SUPPORT"):
        validate_draft(draft, [], set(), [], None, {ref})


def test_knowledge_switch_changes_recovery_and_cache_identity():
    from packages.agent.state import config_version

    enabled = Settings(_env_file=None)
    disabled = enabled.model_copy(update={"knowledge_enabled": False})
    assert config_version(enabled) != config_version(disabled)


def test_official_mapping_objects_match_freeze():
    from packages.knowledge.catalog import verify_sources

    result = verify_sources()
    assert result["techniques"] == 6
    assert result["strategies"] == 6
    assert result["analytics"] >= 6
    assert result["data_components"] >= 1
