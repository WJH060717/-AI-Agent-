"""Route/scope/token-bound opaque cursors. Cursor values are never SQL fragments."""

import base64
import hashlib
import hmac
import json

from packages.storage.service import Actor, DomainError


def encode(actor: Actor, binding: list[str], position: list) -> str:
    raw = json.dumps(
        [1, actor.workspace_id, actor.digest, binding, position], separators=(",", ":")
    ).encode()
    encoded = base64.urlsafe_b64encode(raw).decode()
    signed = sign(actor, encoded.encode())
    return encoded + "." + signed


def decode(actor: Actor, binding: list[str], cursor: str) -> list:
    try:
        if len(cursor) > 4096:
            raise ValueError("cursor length")
        encoded, signed = cursor.split(".")
        expected = sign(actor, encoded.encode())
        if not hmac.compare_digest(signed, expected):
            raise ValueError("signature")
        version, workspace, actor_id, scope, position = json.loads(
            base64.urlsafe_b64decode(encoded)
        )
        if (
            version != 1
            or workspace != actor.workspace_id
            or actor_id != actor.digest
            or scope != binding
            or not isinstance(position, list)
        ):
            raise ValueError("scope")
        return position
    except (ValueError, TypeError, UnicodeError):
        raise DomainError("INVALID_CURSOR", 422) from None


def sign(actor: Actor, message: bytes) -> str:
    if actor.cursor_secret is None:
        raise DomainError("CURSOR_SIGNING_KEY_UNAVAILABLE", 503)
    return hmac.new(
        bytes.fromhex(actor.cursor_secret), b"cursor-v1:" + message, hashlib.sha256
    ).hexdigest()


def validate_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise DomainError("INVALID_LIMIT", 422)


def immutable_page(
    actor: Actor, binding: list[str], items: list[dict], key, limit: int, cursor: str | None
) -> dict:
    validate_limit(limit)
    ordered = sorted(items, key=key)
    if cursor:
        position = decode(actor, binding, cursor)
        if not position or not all(isinstance(v, str) for v in position):
            raise DomainError("INVALID_CURSOR", 422)
        ordered = [item for item in ordered if key(item) > position]
    selected = ordered[:limit]
    return {
        "items": selected,
        "next_cursor": encode(actor, binding, key(selected[-1])) if len(ordered) > limit else None,
    }
