"""R31: pure authentication-failure guessing evidence, separate from R02 success semantics."""

import hashlib
import json
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding
from packages.detection.limits import checkpoint

RULES = Path(__file__).resolve().parents[2] / "rules"


class R31Config(Contract):
    id: Literal["R31"] = "R31"
    version: str = "1.0.0"
    window_seconds: int = Field(default=300, ge=60, le=900)
    min_single_account_failures: int = Field(default=8, ge=5, le=100)
    min_spray_failures: int = Field(default=8, ge=5, le=100)
    min_spray_accounts: int = Field(default=5, ge=3, le=50)
    success_after_seconds: int = Field(default=120, ge=1, le=300)


def load_rule(directory: Path | None = None) -> R31Config:
    directory = directory or RULES
    frozen = json.loads((directory / "auth-guess-freeze.json").read_bytes())
    rule = R31Config.model_validate_json((directory / "R31.json").read_bytes())
    value = rule.model_dump(mode="json")
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if frozen.get("config") != value or frozen.get("config_hash") != digest:
        raise ValueError("AUTH_GUESS_RULE_CONFIGURATION_DRIFT")
    return rule


def _eligible(event: NormalizedEvent) -> bool:
    return bool(
        event.event_type == "auth.login"
        and event.sensor.type == "linux_auth"
        and event.auth
        and event.user
        and event.user.entity_id
        and event.user.realm
        and event.src
        and event.asset_id
        and event.host
        and event.host.boot_id
        and event.host.asset_id == event.asset_id
        and "identity_ambiguous" not in event.quality_flags
    )


def detect_auth_failure_guessing(
    events: list[NormalizedEvent], session_id: str, rule: R31Config | None = None
) -> list[dict]:
    rule = rule or load_rule()
    groups = defaultdict(list)
    for event in {event.event_id: event for event in events}.values():
        checkpoint()
        if not _eligible(event):
            continue
        key = (
            str(event.workspace_id),
            str(event.dataset_id),
            session_id,
            event.sensor.observation_domain,
            event.sensor.sensor_id,
            event.sensor.instance_id,
            event.user.realm,
            str(event.asset_id),
            event.host.boot_id,
            event.auth.service,
            str(event.src.ip),
        )
        groups[key].append(event)
    results = []
    for key, records in groups.items():
        checkpoint()
        ordered = sorted(records, key=lambda e: (e.event_time, e.event_id))
        deduped = {}
        for event in ordered:
            if event.auth.outcome == "unknown":
                continue
            transaction = (
                event.auth.outcome,
                event.user.entity_id,
                event.event_time.isoformat(),
                event.auth.service,
                str(event.src.ip),
                event.src.port,
            )
            deduped.setdefault(transaction, event)
        ordered = list(deduped.values())
        failures = [event for event in ordered if event.auth.outcome == "failure"]
        successes = [event for event in ordered if event.auth.outcome == "success"]
        if not failures:
            continue
        last = failures[-1]
        window_start = last.event_time.timestamp() - rule.window_seconds
        window = [
            event
            for event in failures
            if window_start
            <= event.event_time.timestamp()
            <= last.event_time.timestamp()
        ]
        # A success in the failure window or just after it means R02 (or a
        # separate compromise hypothesis) owns the transition; R31 stays pure.
        if successes and any(
            window[0].event_time - timedelta(seconds=rule.success_after_seconds)
            <= success.event_time
            <= last.event_time + timedelta(seconds=rule.success_after_seconds)
            for success in successes
        ):
            continue
        accounts = {event.user.entity_id for event in window}
        pattern = None
        if len(window) >= rule.min_single_account_failures and len(accounts) == 1:
            pattern = "single_account"
        elif len(window) >= rule.min_spray_failures and len(accounts) >= rule.min_spray_accounts:
            pattern = "multi_account_spray"
        if pattern is None:
            continue
        selected = sorted(
            {event.event_id: event for event in window}.values(),
            key=lambda e: (e.event_time, e.event_id),
        )
        record = finding(
            rule,
            selected,
            session_id,
            [*key, pattern],
            "auth_failure_guessing",
            pattern=pattern,
            failure_count=len(selected),
            distinct_accounts=len(accounts),
            source_ip=str(window[0].src.ip),
            statistics={
                "per_account": {
                    account: sum(1 for event in selected if event.user.entity_id == account)
                    for account in sorted(accounts)
                },
                "window_seconds": rule.window_seconds,
                "success_observed": False,
            },
            interpretation=(
                "连续认证失败候选；可能为正常输错、自动化重试或口令猜测，"
                "不能据此认定使用字典或已入侵成功"
            ),
            limitations=[
                "仅依据认证失败记录和脱敏账号/来源；不证明真实操作者或已获得访问。",
                "未覆盖跨资产、跨来源分布的慢速猜测；空结果不代表没有发生。",
            ],
        )
        results.append(record)
    return sorted(results, key=lambda f: f["id"])