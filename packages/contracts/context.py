from ipaddress import ip_address
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, model_validator

from packages.contracts.models import Contract, Digest, NonNegative, Timestamp

SOURCE_FAMILIES = {
    "pcap_http": "pcap",
    "pcap_packet": "pcap",
    "zeek_http": "zeek",
    "zeek_dns": "zeek",
}


def source_family(source: str) -> str:
    return SOURCE_FAMILIES.get(source, source)


class AddressBinding(Contract):
    ip: str
    observation_domain: str = Field(min_length=1, max_length=100)
    valid_from: Timestamp
    valid_to: Timestamp

    @model_validator(mode="after")
    def valid(self) -> Self:
        self.ip = str(ip_address(self.ip))
        if self.valid_to <= self.valid_from:
            raise ValueError("address interval must be positive")
        return self


class Asset(Contract):
    asset_id: UUID
    hostnames: list[str] = Field(min_length=1, max_length=20)
    addresses: list[AddressBinding] = Field(default_factory=list, max_length=100)


class SensorProfile(Contract):
    sensor_id: str = Field(min_length=1, max_length=200)
    source_type: Literal["pcap", "zeek", "suricata", "linux_auth", "linux_audit", "linux_socket"]
    asset_id: UUID | None = None
    instance_id: str = Field(min_length=1, max_length=200)
    observation_domain: str = Field(min_length=1, max_length=100)
    realm_type: Literal["local", "domain"] = "local"
    realm: str = Field(default="local", min_length=1, max_length=100)
    offset_ms: int = Field(default=0, ge=-3600000, le=3600000)
    uncertainty_ms: int = Field(default=1000, ge=0, le=60000)
    clock_basis: str = Field(min_length=1, max_length=200)


class BaselineWindow(Contract):
    start: Timestamp
    end: Timestamp
    bytes_out: NonNegative

    @model_validator(mode="after")
    def fixed_window(self) -> Self:
        if (self.end - self.start).total_seconds() != 300 or self.start.timestamp() % 300:
            raise ValueError("baseline must use aligned 300-second connection-start windows")
        return self


class EgressBaseline(Contract):
    id: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=50)
    asset_id: UUID
    sensor_id: str = Field(min_length=1, max_length=200)
    instance_id: str = Field(min_length=1, max_length=200)
    observation_domain: str = Field(min_length=1, max_length=100)
    metric: Literal["connection_start_bytes_out@1"] = "connection_start_bytes_out@1"
    purpose: Literal["normal_development_reference"] = "normal_development_reference"
    provenance_type: Literal["synthetic", "real_capture", "derived"]
    source_sha256: Digest
    samples: list[BaselineWindow] = Field(default_factory=list, max_length=120)

    @model_validator(mode="after")
    def nonoverlapping(self) -> Self:
        ordered = sorted(self.samples, key=lambda s: s.start)
        if any(a.end > b.start for a, b in zip(ordered, ordered[1:], strict=False)):
            raise ValueError("baseline windows must be unique and nonoverlapping")
        return self


class DatasetContext(Contract):
    assets: list[Asset] = Field(default_factory=list, max_length=1000)
    sensors: list[SensorProfile] = Field(min_length=1, max_length=100)
    egress_baselines: list[EgressBaseline] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def unique_bindings(self) -> Self:
        assets = {asset.asset_id for asset in self.assets}
        if len(assets) != len(self.assets) or len({s.sensor_id for s in self.sensors}) != len(
            self.sensors
        ):
            raise ValueError("duplicate asset or sensor ID")
        for sensor in self.sensors:
            if sensor.asset_id is not None and sensor.asset_id not in assets:
                raise ValueError("sensor references unknown asset")
            if sensor.source_type.startswith("linux_") and sensor.asset_id is None:
                raise ValueError("Linux sensor requires stable asset binding")
        seen = set()
        for baseline in self.egress_baselines:
            key = (
                baseline.asset_id,
                baseline.sensor_id,
                baseline.instance_id,
                baseline.observation_domain,
            )
            profile = next((s for s in self.sensors if s.sensor_id == baseline.sensor_id), None)
            if (
                key in seen
                or baseline.asset_id not in assets
                or not profile
                or profile.source_type != "zeek"
                or profile.instance_id != baseline.instance_id
                or profile.observation_domain != baseline.observation_domain
            ):
                raise ValueError("baseline requires unique asset and matching Zeek source channel")
            seen.add(key)
        return self
