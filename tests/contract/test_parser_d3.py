import hashlib
import json
from uuid import uuid4

import pytest

from packages.ingest.parsers import ParseContext, parse_record


@pytest.mark.parametrize("duration", [True, "0"])
def test_duration_unit_conversion_rejects_non_numeric_before_multiplication(duration):
    record = {
        "ts": 1794618000,
        "uid": "test",
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 42000,
        "id.resp_h": "10.0.0.20",
        "id.resp_p": 22,
        "proto": "tcp",
        "duration": duration,
    }
    raw = json.dumps(record).encode()
    ctx = ParseContext(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(raw).hexdigest(),
        "sensor",
        "zeek",
        "UTC",
    )
    with pytest.raises(ValueError):
        parse_record(raw, 1, ctx)
