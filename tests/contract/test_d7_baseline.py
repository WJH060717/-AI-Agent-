import pytest
from pydantic import ValidationError

from packages.contracts.context import DatasetContext, EgressBaseline
from tests.contract.test_d7_rules import baseline, connections
from tests.integration.d4_helpers import context_payload


@pytest.mark.parametrize(
    "case", ["duplicate", "overlap", "duration", "negative", "boolean", "hash"]
)
def test_invalid_normal_window_reference_is_rejected(case):
    events, _ = connections()
    data = baseline(events[0]).model_dump(mode="json")
    if case == "duplicate":
        data["samples"].append(data["samples"][0])
    elif case == "overlap":
        data["samples"][0]["start"] = data["samples"][1]["start"]
    elif case == "duration":
        data["samples"][0]["end"] = data["samples"][0]["start"]
    elif case == "negative":
        data["samples"][0]["bytes_out"] = -1
    elif case == "boolean":
        data["samples"][0]["bytes_out"] = True
    else:
        data["source_sha256"] = "pretend"
    with pytest.raises(ValidationError):
        EgressBaseline.model_validate(data)


def test_dataset_rejects_unknown_or_ambiguous_baseline_binding():
    events, _ = connections()
    reference = baseline(events[0]).model_dump(mode="json")
    data = context_payload()
    data["egress_baselines"] = [reference]
    with pytest.raises(ValidationError):
        DatasetContext.model_validate(data)
