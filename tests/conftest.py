"""Public/private test material grouping.

Private acceptance suites stay in the repository for historical reproducibility,
but a missing local archive must be reported as a skip with the exact missing
paths, not as dozens of setup errors on a clean checkout.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_MATERIAL = {
    "test_offline_d14.py": (ROOT / ".tools/d13-wheels", ROOT / "release/d13-kit-02"),
    "test_p1_context_trial.py": (ROOT / ".tools/p1-context-01/trial.py",),
    "test_p1_deepseek_trial.py": (ROOT / ".tools/p1-deepseek-01/trial.py",),
    "test_delivery_d15.py": (ROOT / "release/d14-offline-02.zip",),
    "test_deploy_d13.py": (ROOT / "release/d13-kit-02",),
}


def pytest_collection_modifyitems(config, items):
    for item in items:
        requirements = PRIVATE_MATERIAL.get(Path(str(item.fspath)).name)
        if not requirements:
            continue
        missing = [str(path.relative_to(ROOT)) for path in requirements if not path.exists()]
        if missing:
            item.add_marker(
                pytest.mark.skip(reason="PRIVATE_MATERIAL_MISSING: " + ", ".join(missing))
            )