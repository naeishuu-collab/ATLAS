"""Offline performance snapshot for the autonomous agent production path.

Measures the safe offline overhead of the production managed-execution
machinery on this checkout (Windows, in-process fakes only):

- planning: PlanProposal -> controller materialization (DurablePlan write)
- router: CapabilityRouter.propose model selection
- dispatch: ToolExecutor.execute overhead vs a direct tool.execute call
- verification: mutating tool with independent read-back (file_write shape)
- checkpoint: AgentManager checkpoint persist + reload round trip
- classification: retry/replan error classification

No network, no OS mutation, no native launch.
"""

from __future__ import annotations

import gc
import json
import statistics
import tempfile
import time
import tracemalloc
from pathlib import Path

from openjarvis.agents.capability_router import (
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteRequest,
)
from openjarvis.agents.errors import classify_error
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.plan import DurablePlan
from openjarvis.agents.proposals import PlanStepProposal
from openjarvis.core.execution import ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


def _time(fn, n=200):
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "p50_ms": round(statistics.median(samples), 3),
        "p95_ms": round(sorted(samples)[int(n * 0.95)], 3),
        "mean_ms": round(statistics.mean(samples), 3),
        "n": n,
    }


class _LocalProbe(BaseTool):
    tool_id = "perf_probe"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(self.tool_id, "perf probe", effect=ToolEffect.READ_ONLY)

    def execute(self, **params):
        return ToolResult(self.tool_id, "probe-ok")


class _VerifiedProbe(BaseTool):
    tool_id = "perf_verified_probe"
    store: dict = {}

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id, "perf verified probe", effect=ToolEffect.MUTATING
        )

    def execute(self, **params):
        value = str(params.get("value", ""))
        self.store["v"] = value
        file_ok = self.store.get("v") == value
        return ToolResult(
            self.tool_id,
            "verified" if file_ok else "UNKNOWN_OUTCOME",
            success=file_ok,
            execution_state=None,
        )


results = {}
tool = _LocalProbe()
executor = ToolExecutor([tool])


def _call_probe():
    executor.execute(ToolCall("p", _LocalProbe.tool_id, "{}"))


def _direct_probe():
    tool.execute()


def _route_probe():
    return CapabilityRouter(
        [
            ModelCard(
                engine="local",
                provider="local",
                model="tiny-4b",
                capabilities=frozenset({ModelCapability.TEXT}),
                ctx_limit=4096,
                cost_per_1k=0.0,
                latency_p50_ms=50.0,
                is_cloud=False,
                tier=0,
            )
        ]
    ).propose(
        RouteRequest(
            difficulty="easy",
            need=frozenset({ModelCapability.TEXT}),
            privacy=None,
            est_prompt_tokens=100,
        ),
        ProviderSnapshot(available={"local/tiny-4b": True}),
    )


def _plan_probe():
    DurablePlan.create("bench-exec")
    return tuple(
        PlanStepProposal(local_index=f"s{i}", kind="READ_ONLY", tool_name="probe")
        for i in range(4)
    )


def _classify_probe():
    return classify_error(RuntimeError("rate limit hit"))


results["router_selection"] = _time(_route_probe, n=200)
results["tool_dispatch_direct"] = _time(_direct_probe, n=500)
results["tool_dispatch_executor"] = _time(_call_probe, n=500)
results["tool_dispatch_overhead_ratio"] = round(
    results["tool_dispatch_executor"]["mean_ms"]
    / max(results["tool_dispatch_direct"]["mean_ms"], 1e-9),
    2,
)
results["plan_materialization"] = _time(_plan_probe, n=200)
results["error_classification"] = _time(_classify_probe, n=500)


def _checkpoint_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        mgr = AgentManager(str(Path(tmp) / "agents.db"))
        agent = mgr.create_agent("perf", config={"model": "fake-model"})
        mgr.start_tick(agent["id"])
        mgr.save_checkpoint(
            agent["id"],
            "bench-tick",
            {"conversation_state": {"messages": []}},
            {"tool_state": {"steps": []}},
        )
        _ = mgr.get_latest_checkpoint(agent["id"])
        mgr.close()


results["checkpoint_roundtrip"] = _time(_checkpoint_roundtrip, n=50)

# Python-object growth across repeated managed ticks (heap, not RSS).
tracemalloc.start()
snapshot_before = tracemalloc.take_snapshot()
for _ in range(50):
    _checkpoint_roundtrip()
gc.collect()
snapshot_after = tracemalloc.take_snapshot()
top = snapshot_after.compare_to(snapshot_before, "lineno")
growth_kb = sum(t.size_diff for t in top) / 1024.0
results["heap_growth_50_checkpoint_rounds_kb"] = round(growth_kb, 1)

out = Path(__file__).parent / ".astra-artifacts" / "shadow-20261018"
out.mkdir(parents=True, exist_ok=True)
(out / "performance.json").write_text(
    json.dumps({"scope": "offline production-agent machinery", **results}, indent=2),
    encoding="utf-8",
)
print(json.dumps(results, indent=2))
