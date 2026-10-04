"""Small, additive telemetry for the stages actually executed by a scan."""

from contextlib import contextmanager
from time import perf_counter
from typing import Callable, Optional


STAGES = (
    ("parse", "Parse and normalize", "preparation"),
    ("decode", "Decode obfuscated content", "preparation"),
    ("segment", "Segment and assign trust", "preparation"),
    ("rules", "Rule signatures", "detectors"),
    ("tool", "Tool abuse", "detectors"),
    ("context", "Context poisoning", "detectors"),
    ("jailbreak", "Jailbreak patterns", "detectors"),
    ("indirect", "Indirect injection", "detectors"),
    ("ml", "ML classifier", "detectors"),
    ("sequence", "Multi-segment analysis", "detectors"),
    ("risk", "Risk and policy", "decision"),
    ("llm", "Optional LLM advisory", "decision"),
    ("decision", "Final decision", "decision"),
)

WorkflowCallback = Callable[[list[dict]], None]


class WorkflowTrace:
    """Aggregate timings and findings without changing the scan's control flow.

    Each detector stage can run repeatedly, in the existing per-segment order.
    ``attempts`` counts real stage calls and all timings exclude UI callbacks.
    Callback snapshots contain scalar values only and never input or evidence.
    """

    def __init__(self, on_update: Optional[WorkflowCallback] = None):
        self._stages = {
            stage_id: {
                "id": stage_id,
                "label": label,
                "phase": phase,
                "status": "pending",
                "duration_ms": 0.0,
                "detection_count": 0,
                "attempts": 0,
                "detail": "Waiting to run.",
            }
            for stage_id, label, phase in STAGES
        }
        self._on_update = on_update
        self._last_update = 0.0

    def snapshot(self) -> list[dict]:
        return [dict(stage) for stage in self._stages.values()]

    def publish(self, *, force: bool = False):
        if self._on_update is None:
            return
        now = perf_counter()
        if not force and now - self._last_update < 0.15:
            return
        self._last_update = now
        try:
            self._on_update(self.snapshot())
        except Exception:
            # Presentation must never suppress or change a security result.
            # Engine exceptions are handled separately by step() and re-raised.
            pass

    @contextmanager
    def step(self, stage_id: str, detail: str, *, count_attempt: bool = True):
        stage = self._stages[stage_id]
        first_call = stage["status"] == "pending"
        stage["status"] = "running"
        stage["detail"] = detail
        if count_attempt:
            stage["attempts"] += 1
        self.publish(force=first_call)
        started = perf_counter()
        try:
            yield stage
        except Exception as exc:
            stage["duration_ms"] += (perf_counter() - started) * 1000
            stage["status"] = "error"
            # Exception messages may contain document content or remote details.
            stage["detail"] = f"Stage failed ({type(exc).__name__})."
            self.publish(force=True)
            raise
        else:
            stage["duration_ms"] += (perf_counter() - started) * 1000
            if stage["status"] != "skipped":
                stage["status"] = "completed"
            self.publish(force=stage["phase"] != "detectors")

    def skip(self, stage_id: str, detail: str):
        stage = self._stages[stage_id]
        stage["status"] = "skipped"
        stage["detail"] = detail
        self.publish()
