import json
from pathlib import Path

from packages.contracts.context import DatasetContext
from packages.storage.analysis import AnalysisService
from packages.storage.context import ContextService
from scripts.build_d7_fixture import build


def import_d7(context, variant="positive", audit_records=None):
    settings, _, service, workspace, _ = context
    actor = service.system_actor(workspace)
    root = Path(settings.staging_store) / "d7-fixture"
    build(root)
    dataset = service.create_dataset(actor, {"name": "d7", "provenance_type": "synthetic"}, "d7")
    context_file = "normal_context.json" if variant == "normal" else "context.json"
    ContextService(service).configure(
        actor,
        dataset["dataset_id"],
        DatasetContext.model_validate_json((root / context_file).read_bytes()),
        "ctx",
    )
    for name, source, sensor in (("network", "zeek", "net-a"), ("audit", "linux_audit", "audit-a")):
        filename = "irregular_network" if variant == "irregular" and name == "network" else name
        content = (root / f"{filename}.jsonl").read_bytes()
        if name == "audit" and audit_records is not None:
            content = b"".join((json.dumps(r) + "\n").encode() for r in audit_records)
        service.stage_bytes(
            actor,
            dataset["dataset_id"],
            source,
            sensor,
            "UTC",
            content,
            name,
        )
        service.process_one()
    return actor, dataset, root


def pending_d7(context, budget=None):
    actor, dataset, root = import_d7(context)
    analysis = AnalysisService(context[2])
    incident = analysis.list_incidents(actor, dataset["dataset_id"], dataset["default_session_id"])[
        0
    ]
    run = analysis.create_run(actor, incident["id"], "d7-run", mode="live", budget=budget)
    return actor, dataset, run, root
