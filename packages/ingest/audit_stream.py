"""Checkpoint only fragment locations, never raw command lines or credentials."""

from pathlib import Path

from packages.contracts.models import SourceLocator
from packages.ingest.linux import audit_descriptor, parse_audit_group


def consume(rows, pending: dict, context, path: Path, *, eof: bool):
    output = []
    pending = {key: list(refs) for key, refs in pending.items()}

    def finish(key):
        refs = pending.pop(key)
        try:
            parts = []
            with path.open("rb") as source:
                for ref in refs:
                    source.seek(ref["offset"])
                    raw = source.read(ref["size"])
                    parts.append(
                        (
                            raw,
                            SourceLocator(
                                object_id=context.object_id,
                                raw_sha256=context.sha256,
                                record_start=ref["line"],
                                record_end=ref["line"],
                            ),
                        )
                    )
            event = parse_audit_group(parts, context)
            output.append((refs[0]["line"], event, len(refs)))
        except (ValueError, KeyError, TypeError, OverflowError, UnicodeError):
            output.extend((ref["line"], None, 1) for ref in refs)

    for line, raw, offset in rows:
        try:
            key, record = audit_descriptor(raw, context)
            if key not in pending and len(pending) >= 256:
                raise ValueError("too many pending audit groups")
            refs = pending.setdefault(key, [])
            refs.append(
                {
                    "line": line,
                    "offset": offset,
                    "size": len(raw),
                    "type": record["record_type"],
                    "requires_exec": not (
                        isinstance(record.get("process"), dict)
                        and record["process"].get("action") in {"create", "observe"}
                    ),
                }
            )
            if len(refs) > 64:
                output.extend((r["line"], None, 1) for r in pending.pop(key))
                continue
            types = {r["type"] for r in refs}
            needs_exec = any(r.get("requires_exec", True) for r in refs if r["type"] == "SYSCALL")
            if {"SYSCALL", "EOE"}.issubset(types) and (not needs_exec or "EXECVE" in types):
                finish(key)
        except (ValueError, KeyError, TypeError, OverflowError, UnicodeError):
            output.append((line, None, 1))
    if eof:
        for key in list(pending):
            finish(key)
    return output, pending
