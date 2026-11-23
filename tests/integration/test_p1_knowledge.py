from packages.agent.executor import ToolExecutor
from tests.integration.test_d5_analysis import investigated


def test_knowledge_tool_scoped_bounded_and_disabled(context):
    settings, _, service, _, _ = context
    actor, _, run = investigated(context)
    tools = ToolExecutor(service, actor, run["run_id"])
    result = tools.call("get_technique_context", {"technique_ids": ["T1110", "T9999"]})
    assert result.status == "ok"
    assert len(result.data["items"]) == 1 and result.evidence_ids == []
    assert result.coverage["snapshot_id"] == str(tools.scope.snapshot_id)
    assert "KNOWLEDGE_CONTEXT_ONLY" in result.warnings
    assert "TECHNIQUE_NOT_IN_CURATED_SET" in result.warnings
    assert len(result.model_dump_json().encode()) <= 16384
    settings.knowledge_enabled = False
    empty = tools.call("get_technique_context", {"technique_ids": ["T1110"]})
    assert empty.status == "empty" and "LOCAL_KNOWLEDGE_DISABLED" in empty.warnings


def test_runtime_uses_only_completed_same_run_knowledge(context):
    from packages.agent.runtime import AgentRuntime
    from packages.storage.queue import Queue
    from tests.integration.d6_helpers import pending

    settings, db, service, _, _ = context
    _, _, _ = pending(context, mode="deterministic")
    queue = Queue(db, settings)
    lease = queue.claim("knowledge")
    runtime = AgentRuntime(service, queue, lease)
    result = runtime.tools.call("get_technique_context", {"technique_ids": ["T1110"]})
    ref = result.data["items"][0]["knowledge_ref"]
    runtime.payload["draft"] = {"claims": [{"kind": "unknown", "knowledge_refs": [ref]}]}
    runtime.save("validating", "TEST_UNRETURNED_REFERENCE")
    runtime.step()
    assert "DRAFT_KNOWLEDGE_REFERENCE_OUT_OF_SCOPE" in runtime.payload["rejected"]
    seq, _ = runtime.reserve("tool", "get_technique_context", {"technique_ids": ["T1110"]})
    runtime.finish_action(seq, result.model_dump(mode="json"))
    runtime.save("validating", "TEST_COMPLETED_REFERENCE")
    assert runtime.step()
    assert runtime.payload["validated_claims"][0]["knowledge_refs"] == [ref]
    assert runtime.payload["retrieved"] == []
