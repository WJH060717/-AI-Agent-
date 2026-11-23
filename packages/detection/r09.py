"""Endpoint-only multi-Host callback grouping, explicitly not service identity."""

from typing import Literal

from packages.detection.r08 import R08Config


class R09Config(R08Config):
    id: Literal["R09"] = "R09"
    grouping: Literal["endpoint"] = "endpoint"
    minimum_hosts: Literal[2] = 2
