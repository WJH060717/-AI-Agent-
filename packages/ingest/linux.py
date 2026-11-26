"""Explicit Linux collector JSONL protocol, not an arbitrary syslog text parser."""

import json
import re
from datetime import UTC, datetime
from uuid import UUID

from packages.contracts.context import DatasetContext
from packages.contracts.models import NormalizedEvent, SourceLocator, stable_event_id
from packages.ingest.identity import apply_context, aware, bound_profile, process_key, pseudonym


def integer(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected nonnegative integer")
    return value


def user_fields(record: dict, context, profile, boot: str | None) -> dict | None:
    user = record.get("user")
    if user is None:
        return None
    if not isinstance(user, dict) or not context.identity_salt:
        raise ValueError("invalid user or missing private identity salt")
    if user.get("realm", profile.realm) != profile.realm:
        raise ValueError("account realm conflicts with sensor binding")
    realm = (
        f"local:{profile.asset_id}" if profile.realm_type == "local" else f"domain:{profile.realm}"
    )
    uid = user.get("uid")
    name = user.get("name")
    if name is not None and (not isinstance(name, str) or not 1 <= len(name) <= 200):
        raise ValueError("invalid username")
    identity = None
    if uid is not None:
        if (
            isinstance(uid, bool)
            or not isinstance(uid, (int, str))
            or not re.fullmatch(r"[0-9]{1,20}", str(uid))
        ):
            raise ValueError("uid must be numeric stable account identifier")
        identity = "account:" + pseudonym(context.identity_salt, realm, str(int(uid)))
    session = record.get("session_id")
    if session is not None and (not isinstance(session, str) or not 1 <= len(session) <= 200):
        raise ValueError("invalid session identifier")
    successful = (
        record.get("auth", {}).get("outcome") == "success"
        if isinstance(record.get("auth", {}), dict)
        else False
    )
    session_allowed = context.source_type == "linux_audit" or successful
    return {
        "entity_id": identity,
        "realm": realm,
        "name_redacted": "user-" + pseudonym(context.identity_salt, realm, name or "unknown")[:16],
        "session_id": "session:"
        + pseudonym(context.identity_salt, str(profile.asset_id), boot, session)
        if session_allowed and session and boot and identity
        else None,
    }


def base(record: dict, refs: list[SourceLocator], context) -> dict:
    profile = bound_profile(context)
    if profile is None or profile.asset_id is None:
        raise ValueError("Linux source requires immutable host binding")
    asset = next(
        a
        for a in DatasetContext.model_validate(context.metadata).assets
        if a.asset_id == profile.asset_id
    )
    if record.get("host") not in asset.hostnames:
        raise ValueError("hostname conflicts with configured collector asset")
    boot = record.get("boot_id")
    if boot is not None and (not isinstance(boot, str) or not 1 <= len(boot) <= 200):
        raise ValueError("invalid boot identifier")
    ts = aware(record["timestamp"])
    user = user_fields(record, context, profile, boot)
    return {
        "schema_version": "1.1",
        "workspace_id": context.workspace_id,
        "dataset_id": context.dataset_id,
        "event_id": stable_event_id(
            UUID(context.workspace_id), UUID(context.dataset_id), context.sensor_id, refs
        ),
        "event_time": ts,
        "ingested_at": datetime.now(UTC),
        "time_quality": {
            "original": record["timestamp"],
            "timezone": datetime.fromisoformat(record["timestamp"]).tzname(),
            "offset_ms": 0,
            "uncertainty_ms": 1000,
            "basis": "collector_uncalibrated",
        },
        "sensor": {
            "sensor_id": context.sensor_id,
            "type": context.source_type,
            "instance_id": profile.instance_id,
            "observation_domain": profile.observation_domain,
        },
        "asset_id": profile.asset_id,
        "host": {"asset_id": profile.asset_id, "boot_id": boot},
        "source_locators": refs,
        "parser_version": f"{context.source_type}-json@1.0.0",
        "user": user,
        "quality_flags": (["synthetic"] if record.get("synthetic") is True else [])
        + (["boot_unknown"] if not boot else [])
        + (["identity_weak"] if not user or not user["entity_id"] else []),
    }


def parse_auth(raw: bytes, line: int, context) -> NormalizedEvent:
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError("auth record must be an object")
    ref = SourceLocator(
        object_id=context.object_id, record_start=line, record_end=line, raw_sha256=context.sha256
    )
    payload = base(record, [ref], context)
    payload.update(
        event_type="auth.login",
        auth=record["auth"],
        src={"ip": record["src_ip"], "port": record.get("src_port")},
    )
    if record.get("dest_ip"):
        payload["dst"] = {"ip": record["dest_ip"], "port": record.get("dest_port")}
    return apply_context(NormalizedEvent.model_validate(payload), context)


def parse_socket(raw: bytes, line: int, context) -> NormalizedEvent:
    """Parse one explicit host socket snapshot record.

    The collector must bind the socket to a strong process identity (boot plus
    birth marker) and provide the connection start. A bare PID or an observation
    after the fact is retained as weak evidence and never becomes a graph edge.
    """
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict):
        raise ValueError("socket record must be an object")
    ref = SourceLocator(
        object_id=context.object_id, record_start=line, record_end=line, raw_sha256=context.sha256
    )
    payload = base(record, [ref], context)
    observed = payload["event_time"]
    p = record.get("process")
    if not isinstance(p, dict):
        raise ValueError("socket process must be structured")
    pid = integer(p["pid"])
    action = "observe"
    birth = None
    if p.get("start_ticks") is not None:
        birth = ["ticks", integer(p["start_ticks"])]
    elif p.get("start_time") is not None:
        born = aware(p["start_time"])
        if born > observed:
            raise ValueError("process birth cannot be after socket observation")
        birth = ["time", born.isoformat()]
    strong = bool(
        record.get("boot_id")
        and birth
        and p.get("identity_basis") in {"lifecycle_record", "verified_proc"}
    )
    process = {
        "pid": pid,
        "action": action,
        "boot_id": record.get("boot_id"),
        "identity_basis": p["identity_basis"] if strong else "pid_only",
        "executable": re.sub(r"^/home/[^/]+/", "/home/<user>/", p["executable"])
        if isinstance(p.get("executable"), str)
        else None,
    }
    if strong:
        process["entity_id"] = process_key(payload["asset_id"], record["boot_id"], pid, birth)
        process["start_ticks"] = birth[1] if birth[0] == "ticks" else None
        process["start_time"] = birth[1] if birth[0] == "time" else None
    else:
        payload["quality_flags"].append("identity_weak")
    socket = record.get("socket")
    if not isinstance(socket, dict):
        raise ValueError("socket payload must be structured")
    if socket.get("state") != "established":
        raise ValueError("only established sockets carry a connection binding")
    role = socket.get("role")
    if role not in {"client", "server"}:
        raise ValueError("socket role must be client or server")
    transport = socket.get("transport")
    if transport not in {"tcp", "udp"}:
        raise ValueError("socket transport must be tcp or udp")
    connected = aware(socket.get("connected_at"))
    if connected > observed:
        raise ValueError("connection start cannot be after socket observation")
    inode = socket.get("inode")
    if (
        isinstance(inode, bool)
        or not isinstance(inode, (str, int))
        or not 1 <= len(str(inode)) <= 100
    ):
        raise ValueError("socket inode must be a bounded identifier")
    payload.update(
        event_type="host.process",
        process=process,
        socket={
            "inode": str(inode),
            "role": role,
            "state": "established",
            "connected_at": connected,
        },
        src={"ip": socket["local_ip"], "port": socket["local_port"]},
        dst={"ip": socket["remote_ip"], "port": socket["remote_port"]},
        network={"transport": transport},
    )
    payload["event_time"] = connected
    payload["quality_flags"].append("socket_observation")
    return apply_context(NormalizedEvent.model_validate(payload), context)


def audit_descriptor(raw: bytes, context) -> tuple[str, dict]:
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict) or record.get("record_type") not in {
        "SYSCALL",
        "EXECVE",
        "CWD",
        "PATH",
        "EOE",
    }:
        raise ValueError("unsupported audit record")
    serial = record.get("audit_serial")
    if (
        isinstance(serial, bool)
        or not isinstance(serial, (str, int))
        or not 1 <= len(str(serial)) <= 100
    ):
        raise ValueError("audit serial missing")
    # Validate host/time for every component without retaining raw commands in checkpoints.
    checked = base(
        record,
        [
            SourceLocator(
                object_id=context.object_id, record_start=1, record_end=1, raw_sha256=context.sha256
            )
        ],
        context,
    )
    key = json.dumps(
        [
            str(checked["asset_id"]),
            record.get("boot_id"),
            str(serial),
            checked["event_time"].isoformat(),
        ],
        separators=(",", ":"),
    )
    return key, record


def parse_audit_group(parts: list[tuple[bytes, SourceLocator]], context) -> NormalizedEvent:
    if not parts or len(parts) > 64:
        raise ValueError("audit group exceeds 64 components")
    decoded = [audit_descriptor(raw, context) for raw, _ in parts]
    if len({key for key, _ in decoded}) != 1:
        raise ValueError("audit group identity/time conflict")
    calls = [r for _, r in decoded if r["record_type"] == "SYSCALL"]
    if not calls or any(call != calls[0] for call in calls):
        raise ValueError("missing or conflicting syscall")
    record = calls[0]
    refs = [ref for _, ref in parts]
    payload = base(record, refs, context)
    p = record.get("process")
    if not isinstance(p, dict):
        raise ValueError("syscall process must be structured")
    pid = integer(p["pid"])
    action = p.get("action", "exec")
    complete = any(r["record_type"] == "EOE" for _, r in decoded) and (
        action != "exec" or any(r["record_type"] == "EXECVE" for _, r in decoded)
    )
    birth = None
    if p.get("start_ticks") is not None:
        birth = ["ticks", integer(p["start_ticks"])]
    elif p.get("start_time") is not None:
        born = aware(p["start_time"])
        if born > payload["event_time"]:
            raise ValueError("process birth cannot be after observation")
        birth = ["time", born.isoformat()]
    strong = (
        complete
        and record.get("boot_id")
        and birth
        and p.get("identity_basis") in {"lifecycle_record", "verified_proc"}
    )
    process = {
        "pid": pid,
        "action": action,
        "boot_id": record.get("boot_id"),
        "identity_basis": p["identity_basis"] if strong else "pid_only",
        "executable": re.sub(r"^/home/[^/]+/", "/home/<user>/", p["executable"])
        if isinstance(p.get("executable"), str)
        else None,
    }
    if strong:
        process["entity_id"] = process_key(payload["asset_id"], record["boot_id"], pid, birth)
        process["start_ticks"] = birth[1] if birth[0] == "ticks" else None
        process["start_time"] = birth[1] if birth[0] == "time" else None
        if (
            p.get("ppid") is not None
            and birth[0] == "ticks"
            and p.get("parent_start_ticks") is not None
        ):
            parent_birth = integer(p["parent_start_ticks"])
            if parent_birth > birth[1]:
                payload["quality_flags"].append("parent_identity_conflict")
            else:
                process["parent_entity_id"] = process_key(
                    payload["asset_id"],
                    record["boot_id"],
                    integer(p["ppid"]),
                    ["ticks", parent_birth],
                )
    else:
        payload["quality_flags"].append("identity_weak")
    if not complete:
        payload["quality_flags"].append("partial_audit")
    payload.update(event_type="host.process", process=process)
    if complete and record.get("boot_id"):
        payload["event_id"] = stable_event_id(
            UUID(context.workspace_id),
            UUID(context.dataset_id),
            context.sensor_id,
            refs,
            native_record_id=decoded[0][0],
            instance_id=bound_profile(context).instance_id,
        )
    return apply_context(NormalizedEvent.model_validate(payload), context)
