"""Per-detection resource budget; never silently truncate evaluated evidence."""

from contextvars import ContextVar
from time import monotonic


class DetectionLimit(Exception):
    pass


_active: ContextVar["DetectionBudget | None"] = ContextVar("detection_budget", default=None)


class DetectionBudget:
    def __init__(
        self,
        *,
        work_limit: int = 2_000_000,
        seconds: float = 20,
        byte_limit: int = 268_435_456,
        finding_limit: int = 2000,
        reference_limit: int = 500_000,
    ):
        self.work_limit, self.seconds, self.byte_limit = work_limit, seconds, byte_limit
        self.finding_limit, self.reference_limit = finding_limit, reference_limit
        self.work = self.bytes = self.findings = self.references = 0

    def __enter__(self):
        self.deadline = monotonic() + self.seconds
        self.token = _active.set(self)
        return self

    def __exit__(self, *args):
        _active.reset(self.token)

    def check(self, work: int = 1, *, size: int = 0, references: int | None = None) -> None:
        self.work += work
        self.bytes += size
        if references is not None:
            self.findings += 1
            self.references += references
        if (
            self.work > self.work_limit
            or self.bytes > self.byte_limit
            or self.findings > self.finding_limit
            or self.references > self.reference_limit
            or monotonic() > self.deadline
        ):
            raise DetectionLimit("detection resource budget exhausted")


def checkpoint(work: int = 1, *, size: int = 0, references: int | None = None) -> None:
    budget = _active.get()
    if budget is not None:
        budget.check(work, size=size, references=references)
