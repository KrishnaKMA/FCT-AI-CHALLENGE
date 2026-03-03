# FastAPI backend — REST endpoints for the dashboard polling loop.

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "static"


def create_app(state) -> FastAPI:
    app = FastAPI(
        title="Sentinel AIOps — FCT Command Center",
        description="Autonomous incident response for FCT's real estate transaction platform",
        version="1.0.0",
    )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        index_path = STATIC_DIR / "index.html"
        if index_path.exists():
            return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>Sentinel loading...</h1>")

    @app.get("/api/status")
    async def get_status():
        biz_ctx = state.business_context or {}
        return {
            "timestamp":       datetime.utcnow().isoformat(),
            "system_health":   state.system_health,
            "autonomous_mode": state.autonomous_mode,
            "business_context": biz_ctx,
            "counters":        state.counters,
            "active_faults":   state.active_faults,
            "compliance":      state.compliance_status,
            "prescale_active": getattr(state, "_prescale_done", False),
            "uptime_seconds":  state.uptime_seconds,
        }

    @app.get("/api/metrics")
    async def get_metrics():
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "metrics":   state.current_metrics,
            "health":    state.service_health,
        }

    @app.get("/api/metrics/{service}")
    async def get_service_history(service: str, n: int = 30):
        history = state.metric_history.get(service, [])
        if not history:
            raise HTTPException(404, f"No history for service: {service}")
        return {
            "service": service,
            "history": list(history)[-n:],
        }

    @app.get("/api/incidents")
    async def get_incidents():
        activity = state.activity_log or []
        return {
            "timestamp":    datetime.utcnow().isoformat(),
            "activity_log": activity[-50:],
            "total":        len(activity),
        }

    @app.get("/api/compliance")
    async def get_compliance():
        return state.compliance_status or {"compliant": True, "coverage_pct": 99.8}

    @app.get("/api/graph")
    async def get_graph():
        return state.graph_data or {"nodes": [], "edges": []}

    @app.post("/api/inject/{scenario_id}")
    async def inject_fault(scenario_id: str):
        injector = state.fault_injector
        if not injector:
            raise HTTPException(500, "Fault injector not initialized")
        result = injector.inject(scenario_id)
        if "error" in result:
            raise HTTPException(400, result["error"])
        state.active_faults = injector.get_active_faults()
        return result

    @app.post("/api/resolve/{scenario_id}")
    async def resolve_fault(scenario_id: str):
        injector = state.fault_injector
        if not injector:
            raise HTTPException(500, "Fault injector not initialized")
        injector.resolve(scenario_id)
        state.active_faults = injector.get_active_faults()
        return {"resolved": scenario_id, "timestamp": datetime.utcnow().isoformat()}

    @app.post("/api/resolve-all")
    async def resolve_all_faults():
        injector = state.fault_injector
        if injector:
            for fault in list(injector.get_active_faults()):
                injector.resolve(fault["scenario_id"])
            state.active_faults = []
        return {"resolved": "all", "timestamp": datetime.utcnow().isoformat()}

    @app.post("/api/toggle-autonomous")
    async def toggle_autonomous():
        state.autonomous_mode = not state.autonomous_mode
        return {
            "autonomous_mode": state.autonomous_mode,
            "timestamp":       datetime.utcnow().isoformat(),
        }

    @app.post("/api/simulate-peak")
    async def simulate_peak():
        injector = state.fault_injector
        if injector:
            result = injector.inject("end_of_month_surge")
            state.active_faults = injector.get_active_faults()
            return {"simulated": "friday_closing_surge", "result": result}
        return {"error": "Injector not ready"}

    @app.post("/api/trigger-compliance")
    async def trigger_compliance_incident():
        injector = state.fault_injector
        if injector:
            result = injector.inject("fraud_screening_degradation")
            state.active_faults = injector.get_active_faults()
            return {"simulated": "compliance_incident", "result": result}
        return {"error": "Injector not ready"}

    @app.get("/api/scenarios")
    async def get_scenarios():
        from simulator.fault_scenarios import SCENARIOS, SCENARIO_DESCRIPTIONS
        return [
            {"id": sid, "description": SCENARIO_DESCRIPTIONS.get(sid, sid)}
            for sid in SCENARIOS
        ]

    @app.get("/api/performance")
    async def get_performance():
        if state.feedback_loop:
            return state.feedback_loop.get_performance_summary()
        return {"total_decisions": 0, "overall_success_rate": 0.0}

    return app
