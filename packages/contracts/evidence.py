from uuid import UUID

from pydantic import Field

from packages.contracts.models import (
    ArpReplyObservation,
    ArpRequestObservation,
    Contract,
    Digest,
    NonNegative,
    PacketObservation,
    PcapRecordRange,
    Timestamp,
)


class EvidenceLine(Contract):
    line: int
    text: str


class PcapEvidenceRecord(Contract):
    record_number: NonNegative
    byte_range: PcapRecordRange
    capture_time: Timestamp
    packet: PacketObservation | ArpRequestObservation | ArpReplyObservation
    capture_truncated: bool


class EvidenceFragment(Contract):
    object_id: UUID
    sha256: Digest
    lines: list[EvidenceLine]
    pcap_record: PcapEvidenceRecord | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


class EvidenceResponse(Contract):
    event_id: Digest
    verified: bool
    redacted: bool
    fragments: list[EvidenceFragment]
    next_cursor: str | None = None
