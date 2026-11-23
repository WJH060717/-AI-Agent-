from collections import defaultdict
from pathlib import Path
from typing import Literal

from pydantic import Field

from packages.contracts.models import Contract, NormalizedEvent
from packages.detection.common import finding, strong_process
from packages.detection.limits import checkpoint
from packages.ingest.identity import precedes


class R04Config(Contract):
    id: Literal["R04"] = "R04"
    version: str = "1.0.0"
    window_seconds: int = Field(default=600, ge=1, le=600)
    management_ports: list[int] = Field(min_length=1, max_length=20)


def config() -> R04Config:
    return R04Config.model_validate_json(
        (Path(__file__).resolve().parents[2] / "rules/R04.json").read_bytes()
    )


def detect_remote_access(
    events: list[NormalizedEvent],
    session_id: str,
    sources: list[dict],
    rule: R04Config | None = None,
) -> list[dict]:
    rule = rule or config()
    by_id = {e.event_id: e for e in events}
    networks, logins = defaultdict(list), defaultdict(list)
    for event in events:
        checkpoint()
        scope = (event.workspace_id, event.dataset_id, event.sensor.observation_domain)
        if event.event_type == "network.connection" and event.src:
            networks[(*scope, event.src.asset_id)].append(event)
        if event.event_type == "auth.login" and event.src and event.dst:
            logins[
                (*scope, event.asset_id, event.src.ip, event.dst.ip, event.src.port, event.dst.port)
            ].append(event)
    found = {}
    for seed in sources:
        anchor_id = seed.get("success_id") if seed["rule_id"] == "R02" else seed.get("child_id")
        anchor = by_id.get(anchor_id)
        if not anchor or not anchor.host or not anchor.host.boot_id:
            continue
        if seed["rule_id"] == "R02":
            if not (
                anchor.auth
                and anchor.auth.outcome == "success"
                and anchor.user
                and anchor.user.entity_id
                and anchor.user.session_id
            ):
                continue
        elif seed["rule_id"] != "R03" or not strong_process(anchor):
            continue
        for network in networks[
            (
                anchor.workspace_id,
                anchor.dataset_id,
                anchor.sensor.observation_domain,
                anchor.asset_id,
            )
        ]:
            checkpoint()
            if (
                network.event_type != "network.connection"
                or not network.src
                or not network.dst
                or not network.network
                or network.network.transport != "tcp"
                or network.workspace_id != anchor.workspace_id
                or network.dataset_id != anchor.dataset_id
                or network.sensor.observation_domain != anchor.sensor.observation_domain
                or network.src.asset_id != anchor.asset_id
                or not network.dst.asset_id
                or network.src.resolution_quality != "inventory_interval"
                or network.dst.resolution_quality != "inventory_interval"
                or network.src.asset_id == network.dst.asset_id
                or network.dst.port not in rule.management_ports
                or not precedes(anchor, network, rule.window_seconds)
            ):
                continue
            matching = []
            for login in logins[
                (
                    network.workspace_id,
                    network.dataset_id,
                    network.sensor.observation_domain,
                    network.dst.asset_id,
                    network.src.ip,
                    network.dst.ip,
                    network.src.port,
                    network.dst.port,
                )
            ]:
                checkpoint()
                if (
                    login.event_type != "auth.login"
                    or not login.auth
                    or login.auth.outcome != "success"
                    or not login.host
                    or login.host.asset_id != login.asset_id
                    or not login.host.boot_id
                    or not login.user
                    or not login.user.entity_id
                    or not login.user.session_id
                    or login.asset_id != network.dst.asset_id
                    or not login.src
                    or not login.dst
                    or login.workspace_id != network.workspace_id
                    or login.dataset_id != network.dataset_id
                    or login.sensor.observation_domain != network.sensor.observation_domain
                    or login.src.ip != network.src.ip
                    or login.dst.ip != network.dst.ip
                    or network.src.port is None
                    or login.src.port != network.src.port
                    or login.dst.port != network.dst.port
                    or login.dst.asset_id != login.asset_id
                    or "identity_ambiguous" in login.quality_flags
                ):
                    continue
                uncertainty = (
                    network.time_quality.uncertainty_ms + login.time_quality.uncertainty_ms
                ) / 1000
                if uncertainty <= 8 and precedes(network, login, min(2 + uncertainty, 10)):
                    matching.append(login)
            for login in matching or [None]:
                members = (
                    [by_id[eid] for eid in seed["evidence_ids"]]
                    + [network]
                    + ([login] if login else [])
                )
                item = finding(
                    rule,
                    members,
                    session_id,
                    [seed["id"], network.event_id, login.event_id if login else "no-auth"],
                    "remote_access_candidate" if login else "remote_access_attempt",
                    supporting_findings=[seed],
                    source_anchor_id=anchor.event_id,
                    source_asset_id=str(anchor.asset_id),
                    target_asset_id=str(network.dst.asset_id),
                    network_id=network.event_id,
                    success_id=login.event_id if login else None,
                    missing_steps=["process_socket_binding"]
                    + ([] if login else ["destination_authentication"]),
                    interpretation="可疑源资产之后的跨主机管理访问候选；未证明该进程发起连接或成功横向移动",
                )
                found[item["id"]] = item
    return sorted(found.values(), key=lambda f: f["id"])
