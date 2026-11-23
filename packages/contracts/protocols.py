"""Bounded protocol observations; raw content remains in the local evidence archive."""

import re
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, IPvAnyAddress, StrictBool, StrictInt, StrictStr


def canonical_name(value: str) -> str:
    value = value.lower().rstrip(".")
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    value = value.encode("idna").decode("ascii")
    if not 1 <= len(value) <= 253 or any(
        not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
        for label in value.split(".")
    ):
        raise ValueError("invalid bounded protocol name")
    return value


Name = Annotated[StrictStr, Field(max_length=253), AfterValidator(canonical_name)]
Count = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
Code = Annotated[StrictInt, Field(ge=0, le=65535)]
Suffix = Literal[".exe", ".dll", ".msi", ".scr", ".com", ".elf"]
Mime = Annotated[
    StrictStr, Field(max_length=100, pattern=r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
]


# Imported after scalar definitions to avoid a models/protocols cycle.
from pydantic import BaseModel, ConfigDict, model_validator  # noqa: E402


class HTTPClientShape(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    version: Literal["http-client-shape@1"] = "http-client-shape@1"
    user_agent_class: Literal["browser_compatible", "other", "unknown"]
    query_status: Literal["parsed", "unavailable"]
    query_field_count: Annotated[StrictInt, Field(ge=0, le=64)] | None = None
    opaque_hex_count: Annotated[StrictInt, Field(ge=0, le=64)] | None = None

    @model_validator(mode="after")
    def consistent(self):
        if self.query_status == "parsed":
            if (
                self.query_field_count is None
                or self.opaque_hex_count is None
                or self.opaque_hex_count > self.query_field_count
            ):
                raise ValueError("parsed query requires consistent counts")
        elif self.query_field_count is not None or self.opaque_hex_count is not None:
            raise ValueError("unavailable query counts must remain unknown")
        return self


class HTTPQueryEncoding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["http-query-encoding@1"] = "http-query-encoding@1"
    valid_escapes: Annotated[StrictInt, Field(ge=0, le=16384)]
    escaped_non_ascii: Annotated[StrictInt, Field(ge=0, le=16384)]
    escaped_controls: Annotated[StrictInt, Field(ge=0, le=16384)]
    invalid_percent: Annotated[StrictInt, Field(ge=0, le=16384)]

    @model_validator(mode="after")
    def consistent(self):
        if self.escaped_non_ascii + self.escaped_controls > self.valid_escapes:
            raise ValueError("inconsistent escape counts")
        return self


class HTTPResponseShape(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["http-response-shape@1"] = "http-response-shape@1"
    framing: Literal["complete"]
    body_bytes: Count
    body_format: Literal["empty", "gif", "jpeg", "png", "ico", "gzip", "utf8_text", "other"]


class HTTPObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    transaction_depth: Count | None = None
    method: Annotated[StrictStr, Field(pattern=r"^[A-Z-]{1,32}$")] | None = None
    host: Name | None = None
    uri_suffix: Suffix | None = None
    status_code: Annotated[StrictInt, Field(ge=100, le=599)] | None = None
    request_body_len: Count | None = None
    response_body_len: Count | None = None
    response_mime_types: Annotated[list[Mime], Field(max_length=16)] | None = None
    client_shape: HTTPClientShape | None = None
    query_shape: "HTTPQueryShape | None" = None
    query_encoding: HTTPQueryEncoding | None = None
    response_shape: HTTPResponseShape | None = None


class HTTPQueryShape(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    version: Literal["http-query-shape@1"] = "http-query-shape@1"
    status: Literal["observed", "unavailable"]
    raw_bytes: Annotated[StrictInt, Field(ge=0, le=65536)] | None = None
    raw_non_utf8: StrictBool | None = None
    raw_control_count: Annotated[StrictInt, Field(ge=0, le=65536)] | None = None
    has_literal_kv: StrictBool | None = None
    percent_encoding: Literal["valid", "invalid", "unknown"] = "unknown"
    decoded_non_utf8: StrictBool | None = None
    decoded_control_count: Annotated[StrictInt, Field(ge=0, le=65536)] | None = None

    @model_validator(mode="after")
    def consistent(self):
        raw = [self.raw_bytes, self.raw_non_utf8, self.raw_control_count, self.has_literal_kv]
        decoded = [self.decoded_non_utf8, self.decoded_control_count]
        if self.status == "unavailable":
            if any(v is not None for v in raw + decoded) or self.percent_encoding != "unknown":
                raise ValueError("unavailable byte shape must remain unknown")
        elif (
            any(v is None for v in raw)
            or self.percent_encoding == "unknown"
            or self.raw_control_count > self.raw_bytes
            or (self.percent_encoding == "valid" and any(v is None for v in decoded))
            or (self.percent_encoding == "invalid" and any(v is not None for v in decoded))
            or (
                self.decoded_control_count is not None
                and self.decoded_control_count > self.raw_bytes
            )
        ):
            raise ValueError("inconsistent query byte counts")
        return self


HTTPObservation.model_rebuild()


class DNSObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    query: Name | None = None
    qtype: Code | None = None
    rcode: Code | None = None
    rejected: StrictBool | None = None
    answers: Annotated[list[IPvAnyAddress], Field(max_length=64)] | None = None
    non_ip_answers: Count = 0
    omitted_answers: Count = 0
