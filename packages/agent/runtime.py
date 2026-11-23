"""Lease-fenced persisted Agent. External calls reserve budget before leaving the transaction."""

import json
import queue as thread_queue
import threading
import time
from copy import deepcopy
from uuid import UUID, uuid5

from sqlalchemy import select

from packages.agent.evidence_state import (
    all_actionable_resolved,
    compact_context,
    initialize_analysis,
    update_analysis,
)
from packages.agent.executor import ToolExecutor, summary
from packages.agent.model import CompatibleModel, ModelError
from packages.agent.retrieval import planning_hints
from packages.agent.state import checkpoint, config_version, elapsed
from packages.agent.validation import DraftError, validate_draft
from packages.contracts.agent import DraftDecision, ReportDraft
from packages.graph.paths import analyze_paths
from packages.storage import schema_v5 as t
from packages.storage.service import DomainError, digest, now


class BudgetStop(ValueError):
    pass


class AgentRuntime:
    def __init__(self, service, queue, lease):
        self.service, self.queue, self.lease = service, queue, lease
        self.actor = service.system_actor(lease.workspace_id)
        self.run_id = lease.payload["run_id"]
        self.tools = ToolExecutor(service, self.actor, self.run_id)
        self.paths = analyze_paths(
            self.tools.events, self.tools.scope, set(self.tools.membership["evidence_ids"])
        )
        with service.db.engine.connect() as conn:
            self.findings = [
                service._get(conn, t.findings, self.actor, fid)["payload"]
                for fid in self.tools.membership["finding_ids"]
            ]
        self.model = CompatibleModel(service.settings)
        self.reload()

    def reload(self):
        with self.service.db.engine.connect() as conn:
            row = self.service._get(conn, t.agent_states, self.actor, self.run_id)
            self.phase, self.version, self.payload = (
                row["phase"],
                row["version"],
                deepcopy(row["payload"]),
            )

    def guard(self):
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, self.lease)

    def save(self, phase, reason, conn=None):
        if conn is None:
            with self.service.db.engine.begin() as transaction:
                return self.save(phase, reason, transaction)
        self.queue.guard(conn, self.lease)
        self.version = checkpoint(
            conn, self.actor.workspace_id, self.run_id, self.version, phase, self.payload, reason
        )
        self.phase = phase

    def bounded(self, fn, seconds):
        self.guard()
        if seconds <= 0:
            raise TimeoutError("EXTERNAL_TIMEOUT")
        channel = thread_queue.Queue(maxsize=1)

        def work():
            try:
                channel.put((True, fn()))
            except Exception as exc:
                channel.put((False, exc))

        threading.Thread(target=work, daemon=True).start()
        deadline = time.monotonic() + seconds
        completed = False
        try:
            while True:
                self.guard()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("EXTERNAL_TIMEOUT")
                try:
                    ok, value = channel.get(timeout=min(0.1, remaining))
                    self.guard()
                    if ok:
                        completed = True
                        return value
                    raise value
                except thread_queue.Empty:
                    continue
        finally:
            if not completed:
                self.model.cancel_current()

    def remaining_time(self):
        return self.payload["budget"]["timeout_seconds"] - elapsed(self.payload)

    def actions(self):
        with self.service.db.engine.connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    select(t.agent_actions)
                    .where(
                        t.agent_actions.c.workspace_id == self.actor.workspace_id,
                        t.agent_actions.c.run_id == self.run_id,
                    )
                    .order_by(t.agent_actions.c.seq)
                ).mappings()
            ]

    def reserve(self, kind, name, args, input_tokens=0, output_tokens=0, wait_ms=0):
        used, budget = self.payload["used"], self.payload["budget"]
        from packages.agent.cost import estimate_cost

        try:
            cost = (
                estimate_cost(self.service.settings, input_tokens, output_tokens)
                if kind == "model"
                else 0
            )
        except ValueError as exc:
            raise BudgetStop(str(exc)) from None
        if used.get("cost_microusd", 0) + cost > (budget.get("max_cost_microusd") or 0):
            raise BudgetStop("MODEL_COST_BUDGET_EXHAUSTED")
        if self.remaining_time() <= 0:
            raise BudgetStop("WALLCLOCK_BUDGET_EXHAUSTED")
        if used[kind + "_calls"] >= budget["max_" + kind + "_calls"]:
            raise BudgetStop(kind.upper() + "_CALL_BUDGET_EXHAUSTED")
        if (
            used["input_tokens"] + input_tokens > budget["max_input_tokens"]
            or used["output_tokens"] + output_tokens > budget["max_output_tokens"]
            or used["model_wait_ms"] + wait_ms > budget["model_wait_seconds"] * 1000
        ):
            raise BudgetStop("MODEL_TOKEN_OR_WAIT_BUDGET_EXHAUSTED")
        seq = self.payload["next_seq"]
        self.payload["next_seq"] += 1
        self.payload["pending_action"] = seq
        used[kind + "_calls"] += 1
        used["input_tokens"] += input_tokens
        used["output_tokens"] += output_tokens
        used["model_wait_ms"] += wait_ms
        used["cost_microusd"] = used.get("cost_microusd", 0) + cost
        used.setdefault("actual_cost_microusd", 0)
        reservation = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model_wait_ms": wait_ms,
            "cost_microusd": cost,
        }
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, self.lease)
            conn.execute(
                t.agent_actions.insert().values(
                    workspace_id=self.actor.workspace_id,
                    run_id=self.run_id,
                    seq=seq,
                    kind=kind,
                    name=name,
                    status="reserved",
                    args_hash=digest(json.dumps(args, sort_keys=True).encode()),
                    args_payload=args,
                    usage=reservation,
                    started_at=now(),
                )
            )
            self.save(self.phase, "RESERVED_" + kind.upper(), conn)
        return seq, reservation

    def finish_action(
        self,
        seq,
        result,
        status="completed",
        code=None,
        request_id=None,
        actual_usage=None,
        reservation=None,
        new_count=0,
        phase=None,
    ):
        if actual_usage is not None:
            # Keep the conservative reservation charged; actual is a separate estimate.
            self.payload["used"]["actual_cost_microusd"] += actual_usage.get(
                "actual_cost_microusd", 0
            )
            for key in ("input_tokens", "output_tokens", "model_wait_ms"):
                self.payload["used"][key] -= reservation[key] - actual_usage[key]
        self.payload["pending_action"] = None
        with self.service.db.engine.begin() as conn:
            self.queue.guard(conn, self.lease)
            conn.execute(
                t.agent_actions.update()
                .where(
                    t.agent_actions.c.workspace_id == self.actor.workspace_id,
                    t.agent_actions.c.run_id == self.run_id,
                    t.agent_actions.c.seq == seq,
                    t.agent_actions.c.status == "reserved",
                )
                .values(
                    status=status,
                    result_payload=result,
                    result_digest=digest(json.dumps(result, sort_keys=True).encode())
                    if result is not None
                    else None,
                    request_id=request_id,
                    error_code=code,
                    ended_at=now(),
                    new_evidence_count=new_count,
                    usage=actual_usage if actual_usage is not None else reservation,
                )
            )
            self.save(phase or self.phase, code or "ACTION_COMPLETED", conn)

    def context(self, kind: str = "plan") -> dict:
        known = set(self.tools.membership["evidence_ids"]) | set(self.payload["retrieved"])
        available = [e for e in self.tools.events if e.event_id in known]
        new_ids = set(self.payload["retrieved"]) - set(self.tools.membership["evidence_ids"])
        actions = self.actions()
        chosen = (
            [e for e in available if e.event_id in new_ids][:2]
            + [e for e in available if e.auth][:2]
            + [self.tools.by_id[eid] for eid in self.payload["retrieved"][:4]]
            + [e for e in available if not e.auth][:2]
        )
        facts = list({e.event_id: summary(e) for e in chosen}.values())[:6]
        results = [
            {
                "name": action["name"],
                "evidence_ids": action["result_payload"].get("evidence_ids", [])[:4],
                "new_evidence_count": action["new_evidence_count"],
                "arguments": action["args_payload"],
                "next_cursor": action["result_payload"].get("next_cursor"),
                "truncated": action["result_payload"].get("truncated", False),
                "coverage": action["result_payload"].get("coverage", {}),
                "warnings": action["result_payload"].get("warnings", []),
                "data": action["result_payload"].get("data", {}).get("items", [])[:1],
            }
            for action in actions
            if action["kind"] == "tool" and action["status"] == "completed"
        ][-2:]
        for result in results:
            if kind == "plan":
                result["data"] = "omitted_for_planning; see facts"
            elif len(json.dumps(result).encode()) > 2000:
                result["data"] = "truncated_for_model; query bounded tools for further detail"
        context = {
            "run_id": self.run_id,
            "incident_id": self.tools.incident_id,
            "scope": self.tools.scope.model_dump(mode="json"),
            "facts": facts,
            "facts_truncated": len(available) > len(facts),
            "seed_event_ids": self.tools.membership["evidence_ids"][:20],
            "seed_ids_truncated": len(self.tools.membership["evidence_ids"]) > 20,
            "retrieved_event_ids": self.payload["retrieved"][:30],
            "tool_results": results,
            "budget": self.payload["budget"],
            "budget_used": self.payload["used"],
            "validation_errors": self.payload["rejected"][-1:],
            "investigation": compact_context(self.payload),
            "data_trust": "untrusted",
        }
        if kind == "plan":
            context["retrieval"] = planning_hints(
                available,
                set(self.tools.membership["evidence_ids"]),
                set(self.payload["retrieved"]),
                actions,
                context["investigation"],
                results,
            )
        return context

    def model_call(self, kind):
        budget, used = self.payload["budget"], self.payload["used"]
        output = min(
            self.service.settings.model_output_tokens_per_call,
            budget["max_output_tokens"] - used["output_tokens"],
        )
        seconds = min(
            self.service.settings.model_timeout_seconds,
            self.remaining_time(),
            budget["model_wait_seconds"] - used["model_wait_ms"] / 1000,
        )
        if output <= 0 or seconds <= 0:
            raise BudgetStop("MODEL_TOKEN_OR_WAIT_BUDGET_EXHAUSTED")
        context = self.context(kind)
        request = self.model.request(kind, context, output)
        available_input = budget["max_input_tokens"] - used["input_tokens"]
        # Preserve continuation and scope metadata when compacting. Removing it turns a
        # valid next-page request into a repeat of the first page.
        if len(request) > available_input:
            for result in context["tool_results"]:
                result["data"] = "omitted_for_input_budget"
            request = self.model.request(kind, context, output)
        while len(request) > available_input and context["facts"]:
            context["facts"].pop()
            context["facts_truncated"] = True
            request = self.model.request(kind, context, output)
        seq, reserved = self.reserve(
            "model",
            kind,
            {"phase": kind, "request_digest": digest(request)},
            len(request),
            output,
            int(seconds * 1000),
        )
        try:
            result = self.bounded(
                lambda: self.model.complete(request, kind, timeout=seconds), seconds
            )
        except (ModelError, TimeoutError) as exc:
            code = str(exc) if isinstance(exc, ModelError) else "MODEL_TIMEOUT"
            self.payload["stop_reason"] = code
            self.finish_action(seq, None, "failed", code, reservation=reserved, phase="degraded")
            return None
        actual = {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "model_wait_ms": min(reserved["model_wait_ms"], result.elapsed_ms),
            "cost_microusd": reserved["cost_microusd"],
        }
        from packages.agent.cost import estimate_cost

        actual["actual_cost_microusd"] = estimate_cost(
            self.service.settings, result.input_tokens, result.output_tokens
        )
        if kind == "plan":
            self.payload["planning_rounds"] += 1
            if isinstance(result.value, DraftDecision):
                self.payload["query_stop_reason"] = "MODEL_REQUESTED_DRAFT"
                phase = "drafting"
            else:
                decision = result.value.model_dump(mode="json")
                try:
                    decision["arguments"] = self.tools.validate(
                        decision["tool"], decision["arguments"]
                    ).model_dump(mode="json")
                except DomainError as exc:
                    decision = {
                        "action": "call_tool",
                        "tool": "rejected_tool",
                        "arguments": {},
                        "reason_summary": "Policy rejected the requested tool arguments",
                        "expected_evidence": "none",
                        "policy_error": exc.code,
                    }
                self.payload["pending_tool"] = decision
                phase = "querying"
        else:
            self.payload["draft"] = result.value.model_dump(mode="json")
            phase = "validating"
        self.finish_action(
            seq,
            self.payload["pending_tool"]
            if kind == "plan" and self.payload["pending_tool"]
            else result.value.model_dump(mode="json"),
            request_id=result.request_id,
            actual_usage=actual,
            reservation=reserved,
            phase=phase,
        )
        return result

    def tool_call(self):
        decision = self.payload["pending_tool"]
        tool, arguments = decision["tool"], decision["arguments"]
        try:
            if decision.get("policy_error"):
                raise DomainError(decision["policy_error"], 422)
            args = self.tools.validate(tool, arguments)
            normalized = args.model_dump(mode="json")
            error = None
        except DomainError as exc:
            normalized, error = {"rejected_arguments": True}, exc.code
        key = digest(json.dumps(normalized, sort_keys=True).encode())
        cached = (
            next(
                (
                    a
                    for a in self.actions()
                    if a["kind"] == "tool"
                    and a["name"] == tool
                    and a["args_hash"] == key
                    and a["status"] == "completed"
                ),
                None,
            )
            if error is None
            else None
        )
        if cached:
            self.payload["cache_hits"] += 1
            self.payload["no_new"] += 1
            self.payload["pending_tool"] = None
            self.save("checking", "TOOL_RESULT_REUSED")
            return
        seq, reserved = self.reserve("tool", tool if error is None else "rejected_tool", normalized)
        if error:
            self.payload["stop_reason"] = error
            self.payload["pending_tool"] = None
            self.finish_action(seq, None, "rejected", error, reservation=reserved, phase="degraded")
            return
        call_id = str(uuid5(UUID(self.run_id), str(seq)))
        try:
            result = self.bounded(
                lambda: self.tools.call(tool, normalized, call_id),
                min(self.service.settings.tool_timeout_seconds, self.remaining_time()),
            )
        except (DomainError, TimeoutError) as exc:
            code = exc.code if isinstance(exc, DomainError) else "TOOL_TIMEOUT"
            self.payload["stop_reason"] = code
            self.finish_action(seq, None, "failed", code, reservation=reserved, phase="degraded")
            return
        seen = set(self.tools.membership["evidence_ids"]) | set(self.payload["retrieved"])
        new_ids = set(result.evidence_ids) - seen
        self.payload["retrieved"] = sorted(
            set(self.payload["retrieved"]) | set(result.evidence_ids)
        )
        self.payload["no_new"] = 0 if new_ids else self.payload["no_new"] + 1
        self.payload["pending_tool"] = None
        update_analysis(self.payload, self.tools, self.findings, seq)
        self.finish_action(
            seq,
            result.model_dump(mode="json"),
            new_count=len(new_ids),
            reservation=reserved,
            phase="checking",
        )

    def step(self) -> bool:
        self.reload()
        self.guard()
        if self.phase in {"completed", "partial"}:
            return True
        if self.phase != "degraded" and self.payload["model_config_version"] != config_version(
            self.service.settings
        ):
            self.payload["stop_reason"] = "MODEL_CONFIGURATION_CHANGED"
            self.save("degraded", "MODEL_CONFIGURATION_CHANGED")
            return False
        if self.phase != "degraded" and self.remaining_time() <= 0:
            self.payload["stop_reason"] = "WALLCLOCK_BUDGET_EXHAUSTED"
            self.save("degraded", "WALLCLOCK_BUDGET_EXHAUSTED")
            return False
        if self.payload["pending_action"] is not None:
            # An interrupted request may already have reached the provider.
            # Never refund its reservation.
            seq = self.payload["pending_action"]
            self.finish_action(
                seq,
                None,
                "abandoned",
                "INTERRUPTED_CALL_REMAINS_CHARGED",
                reservation=next(a["usage"] for a in self.actions() if a["seq"] == seq),
                phase=self.phase,
            )
            return False
        try:
            if self.phase == "queued":
                self.payload["started_at"] = now()
                self.save("preparing", "STARTED")
            elif self.phase == "preparing":
                initialize_analysis(self.payload, self.tools, self.findings)
                if self.payload["model_config_version"] != config_version(self.service.settings):
                    raise BudgetStop("MODEL_CONFIGURATION_CHANGED")
                intentional = self.payload["requested_mode"] == "deterministic" or (
                    self.payload["requested_mode"] == "auto"
                    and self.service.settings.model_provider == "disabled"
                )
                if intentional:
                    self.payload["query_stop_reason"] = "DETERMINISTIC_MODE"
                    self.save("drafting", "EXPLICIT_DETERMINISTIC_MODE")
                elif self.service.settings.model_provider == "disabled":
                    raise BudgetStop("MODEL_DISABLED")
                else:
                    self.save("planning", "MODEL_PLANNING")
            elif self.phase == "planning":
                self.model_call("plan")
            elif self.phase == "querying":
                self.tool_call()
            elif self.phase == "checking":
                distinct = {
                    a["name"]
                    for a in self.actions()
                    if a["kind"] == "tool" and a["status"] == "completed"
                }
                reason = (
                    "NO_NEW_EVIDENCE"
                    if self.payload["no_new"] >= 2
                    else "ACTIONABLE_GAPS_RESOLVED"
                    if len(distinct) >= 2 and all_actionable_resolved(self.payload)
                    else "MAX_PLANNING_ROUNDS"
                    if self.payload["planning_rounds"] >= 2
                    else None
                )
                if reason:
                    self.payload["query_stop_reason"] = reason
                    self.save("drafting", reason)
                else:
                    self.save("planning", "NEED_MORE_EVIDENCE")
            elif self.phase == "drafting":
                if self.payload["requested_mode"] == "deterministic" or (
                    self.payload["requested_mode"] == "auto"
                    and self.service.settings.model_provider == "disabled"
                ):
                    self.payload["draft"] = ReportDraft().model_dump()
                    self.save("validating", "DETERMINISTIC_FACTS_ONLY")
                else:
                    self.model_call("draft")
            elif self.phase == "validating":
                try:
                    draft = ReportDraft.model_validate(self.payload["draft"])
                    claims = validate_draft(
                        draft,
                        self.tools.events,
                        set(self.tools.membership["evidence_ids"]) | set(self.payload["retrieved"]),
                        self.findings,
                        self.paths,
                        {
                            item["knowledge_ref"]
                            for action in self.actions()
                            if action["kind"] == "tool"
                            and action["name"] == "get_technique_context"
                            and action["status"] == "completed"
                            for item in (action["result_payload"] or {})
                            .get("data", {})
                            .get("items", [])
                            if "knowledge_ref" in item
                        },
                    )
                except DraftError as exc:
                    self.payload["rejected"].append(str(exc))
                    if (
                        self.payload["repair_count"] == 0
                        and self.payload["used"]["model_calls"]
                        < self.payload["budget"]["max_model_calls"]
                    ):
                        self.payload["repair_count"] = 1
                        self.save("drafting", "ONE_DRAFT_REPAIR")
                    else:
                        raise BudgetStop("DRAFT_VALIDATION_FAILED") from None
                else:
                    self.payload["validated_claims"] = [
                        claim.model_dump(mode="json") for claim in claims
                    ]
                    if self.payload["used"]["model_calls"]:
                        self.payload["report_mode"] = "live"
                    self.save("completed", "VALIDATED")
            elif self.phase == "degraded":
                self.payload["report_mode"] = "deterministic_fallback"
                self.save("partial", self.payload["stop_reason"] or "DEGRADED")
            else:
                raise RuntimeError("Unknown Agent phase")
            if (
                self.phase not in {"partial", "completed", "degraded"}
                and self.remaining_time() <= 0
            ):
                raise BudgetStop("WALLCLOCK_BUDGET_EXHAUSTED")
        except BudgetStop as exc:
            self.payload["stop_reason"] = str(exc)
            self.save("degraded", str(exc))
        return self.phase in {"completed", "partial"}

    def run(self) -> dict:
        while not self.step():
            pass
        return deepcopy(self.payload) | {"terminal": self.phase}
