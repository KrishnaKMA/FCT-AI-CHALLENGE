# FCT AI Challenge — AIOps Incident Response Agent
# Run: python main.py  (or python main.py --demo)  → http://localhost:8000

import sys
import os
import time
import random
import threading
import webbrowser
import logging
import argparse
from datetime import datetime
from collections import deque
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from simulator.closing_calendar  import ClosingCalendar
from simulator.fct_environment   import FCTEnvironment
from simulator.fault_scenarios   import FaultInjector
from agent.anomaly_detector      import AnomalyDetector, SKLEARN_AVAILABLE
from agent.rca_engine            import RCAEngine
from agent.compliance_monitor    import ComplianceMonitor
from agent.remediation           import RemediationEngine
from agent.feedback_loop         import FeedbackLoop
from dashboard.api               import create_app

import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sentinel")


class SharedState:
    def __init__(self):
        self._lock = threading.Lock()

        self.current_metrics:  dict = {}
        self.metric_history: dict[str, deque] = {
            svc: deque(maxlen=60)
            for svc in [
                "policy-issuance-service",
                "fraud-screening-service",
                "title-search-service",
                "identity-verification-service",
                "mortgage-processing-service",
                "document-vault-service",
                "property-intelligence-api",
            ]
        }
        self.service_health:    dict[str, float] = {}
        self.system_health:     float = 100.0
        self.activity_log:      list  = []
        self.current_anomalies: list  = []
        self.business_context:  dict  = {}
        self.compliance_status: dict  = {"compliant": True, "coverage_pct": 99.8}
        self.fault_injector     = None
        self.feedback_loop      = None
        self.graph_data:        dict  = {}
        self.counters: dict = {
            "transactions_today":           0,
            "policies_issued":              0,
            "fraud_screens_completed":      0,
            "fraud_screen_coverage_pct":    99.8,
            "closing_deadlines_at_risk":    0,
            "incidents_auto_resolved":      0,
            "incidents_escalated":          0,
            "estimated_closings_protected": 0,
        }
        self.active_faults:    list = []
        self.autonomous_mode:  bool = True
        self._prescale_done:   bool = False
        self._start_time = time.monotonic()

    @property
    def uptime_seconds(self) -> float:
        return round(time.monotonic() - self._start_time, 1)

    def update_metrics(self, metrics: dict):
        with self._lock:
            self.current_metrics = metrics
            ts = datetime.utcnow().isoformat()
            for svc, m in metrics.items():
                if svc in self.metric_history:
                    self.metric_history[svc].append({"timestamp": ts, "metrics": dict(m)})

    def update_health(self, service_health: dict, anomalies: list):
        with self._lock:
            new_health = {svc: 100.0 for svc in self.metric_history}
            for a in anomalies:
                svc = a.get("service")
                if svc and svc in new_health:
                    conf    = a.get("confidence", 0.5)
                    breach  = a.get("compliance_breach", False)
                    penalty = 60.0 if breach else 40.0 * conf
                    new_health[svc] = max(0.0, new_health[svc] - penalty)
            self.service_health    = new_health
            self.system_health     = round(sum(new_health.values()) / max(1, len(new_health)), 1)
            self.current_anomalies = anomalies


def simulator_loop(state: SharedState, env: FCTEnvironment, fault_inj: FaultInjector):
    log.info("Simulator started")
    while True:
        try:
            fault_inj.tick()
            metrics = env.tick()
            state.update_metrics(metrics)

            biz_ctx = env.calendar.get_context()
            state.business_context = biz_ctx
            state.active_faults    = fault_inj.get_active_faults()

            with state._lock:
                state.counters["transactions_today"]      = env.transactions_today
                state.counters["policies_issued"]         = env.policies_issued
                state.counters["fraud_screens_completed"] = env.fraud_screens_completed
                cov = metrics.get("fraud-screening-service", {}).get("fraud_screen_coverage_pct", 99.8)
                state.counters["fraud_screen_coverage_pct"]  = round(cov, 2)
                state.counters["closing_deadlines_at_risk"]  = biz_ctx.get("active_transactions_at_risk", 0)

        except Exception as e:
            log.error(f"Simulator error: {e}")

        time.sleep(5)


def agent_loop(
    state:       SharedState,
    detector:    AnomalyDetector,
    rca:         RCAEngine,
    compliance:  ComplianceMonitor,
    remediation: RemediationEngine,
    feedback:    FeedbackLoop,
):
    log.info("Agent loop started")
    cycle = 0

    while True:
        try:
            metrics = state.current_metrics
            biz_ctx = state.business_context
            if not metrics:
                time.sleep(10)
                continue

            cycle += 1

            compliance_status = compliance.check(metrics, biz_ctx)
            state.compliance_status = compliance_status

            anomalies = detector.detect(metrics)
            state.update_health({}, anomalies)

            if anomalies:
                log.info(f"[Cycle {cycle}] {len(anomalies)} anomaly(ies): {[a['service'] for a in anomalies]}")

            rca_result = None
            if anomalies or not compliance_status.get("compliant"):
                rca_result = rca.analyze(anomalies, metrics, biz_ctx)
                log.info(
                    f"[Cycle {cycle}] RCA: root={rca_result.get('root_cause')}, "
                    f"type={rca_result.get('anomaly_type')}, "
                    f"conf={rca_result.get('confidence', 0):.2f}"
                )

            if rca_result and rca_result.get("root_cause"):
                pre_scores = {
                    a["service"]: a.get("confidence", 0)
                    for a in anomalies if a.get("service")
                }
                decision = remediation.decide_and_act(rca_result, compliance_status, biz_ctx, anomalies)
                if decision:
                    feedback.register_decision(decision, pre_scores)
                    log.info(
                        f"[Cycle {cycle}] Action: {decision.get('actions_taken')} "
                        f"({'autonomous' if decision.get('autonomous') else 'recommended'})"
                    )

            feedback.check_outcomes(metrics, anomalies)

            prescale_decision = remediation.prescale_for_upcoming_peak(biz_ctx)
            if prescale_decision:
                log.info(f"[Cycle {cycle}] Proactive prescale triggered")

            if not biz_ctx.get("pre_scale_recommended") and getattr(state, "_prescale_done", False):
                state._prescale_done = False

        except Exception as e:
            log.error(f"Agent loop error: {e}", exc_info=True)

        time.sleep(10)


def auto_fault_injection(fault_inj: FaultInjector):
    log.info("Auto fault injection — first fault in 90 seconds")
    time.sleep(90)

    scenarios = [
        "end_of_month_surge",
        "fraud_screening_degradation",
        "title_search_timeout",
        "identity_verification_bottleneck",
        "document_vault_disk_saturation",
        "suspicious_transaction_velocity",
        "cascading_policy_failure",
    ]
    weights = [3, 1, 3, 3, 2, 2, 1]

    while True:
        try:
            scenario   = random.choices(scenarios, weights=weights)[0]
            active_ids = [f["scenario_id"] for f in fault_inj.get_active_faults()]
            if scenario not in active_ids:
                log.info(f"Auto-injecting: {scenario}")
                fault_inj.inject(scenario)
        except Exception as e:
            log.error(f"Auto fault injection error: {e}")

        wait = random.randint(120, 240)
        log.info(f"Next auto fault in {wait}s")
        time.sleep(wait)


DEMO_SCENARIOS = [
    ("end_of_month_surge",                "End-of-month load surge (LOAD_SURGE)"),
    ("fraud_screening_degradation",       "Fraud screening memory leak (COMPLIANCE_INCIDENT)"),
    ("title_search_timeout",              "Land registry API timeout (EXTERNAL_DEPENDENCY)"),
    ("identity_verification_bottleneck",  "KYC queue bottleneck (INFRASTRUCTURE_FAILURE)"),
    ("document_vault_disk_saturation",    "Document vault disk saturation (STORAGE_SATURATION)"),
    ("suspicious_transaction_velocity",   "Suspicious transaction velocity (FRAUD_SIGNAL)"),
    ("cascading_policy_failure",          "Cascading policy failure (CASCADE)"),
]


def demo_fault_injection(fault_inj: FaultInjector):
    log.info("=" * 60)
    log.info("DEMO MODE — Sequential fault injection starting in 30s")
    log.info("7 scenarios × 45s gaps = ~5.5 minutes total")
    log.info("=" * 60)
    time.sleep(30)

    for i, (scenario_id, description) in enumerate(DEMO_SCENARIOS, 1):
        log.info(f"[DEMO {i}/7] {description}")

        try:
            fault_inj.resolve_all()
        except Exception:
            pass

        try:
            fault_inj.inject(scenario_id)
            log.info(f"[DEMO {i}/7] Fault active — agent has 45s to detect and remediate")
        except Exception as e:
            log.error(f"[DEMO {i}/7] Failed to inject {scenario_id}: {e}")

        time.sleep(45)

    try:
        fault_inj.resolve_all()
    except Exception:
        pass

    log.info("=" * 60)
    log.info("DEMO COMPLETE — All 7 scenarios demonstrated")
    log.info("Dashboard remains live. Press Ctrl+C to stop.")
    log.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="FCT AI Challenge — AIOps Incident Response Agent")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Inject all 7 fault scenarios sequentially, 45s apart, starting 30s after launch.",
    )
    args      = parser.parse_args()
    demo_mode = args.demo

    print(
        "\n" + "=" * 66 + "\n"
        "  FCT AI CHALLENGE -- AIOps Incident Response Agent\n"
        "  Autonomous monitoring for FCT's real estate transaction\n"
        "  processing platform.\n\n"
        "  Starting subsystems...\n"
        + "=" * 66 + "\n"
    )

    state     = SharedState()
    calendar  = ClosingCalendar()
    env       = FCTEnvironment(calendar)
    fault_inj = FaultInjector(env)

    if SKLEARN_AVAILABLE:
        log.info("Generating synthetic training data for IsolationForest...")
    else:
        log.warning(
            "scikit-learn not installed — running in Z-score-only detection mode. "
            "Install via: python -m venv venv && venv\\Scripts\\activate && pip install -r requirements.txt"
        )
    training_data = env.generate_training_data(n_samples=200)
    detector      = AnomalyDetector(calendar)
    detector.train(training_data)
    log.info(
        "Anomaly detector ready — "
        + ("IsolationForest + Z-score active" if SKLEARN_AVAILABLE else "Z-score + compliance layers active")
    )

    rca_engine = RCAEngine()
    state.graph_data = rca_engine.get_dependency_graph_data()

    compliance_mon = ComplianceMonitor(env)
    feedback       = FeedbackLoop(state, env)
    remediation    = RemediationEngine(env, state)

    state.fault_injector = fault_inj
    state.feedback_loop  = feedback

    threads = [
        threading.Thread(target=simulator_loop, args=(state, env, fault_inj), daemon=True, name="simulator"),
        threading.Thread(target=agent_loop,     args=(state, detector, rca_engine, compliance_mon, remediation, feedback), daemon=True, name="agent"),
    ]

    if demo_mode:
        threads.append(threading.Thread(target=demo_fault_injection, args=(fault_inj,), daemon=True, name="demo-injector"))
    else:
        threads.append(threading.Thread(target=auto_fault_injection, args=(fault_inj,), daemon=True, name="fault-injector"))

    for t in threads:
        t.start()
        log.info(f"Started thread: {t.name}")

    def open_browser():
        time.sleep(2.5)
        try:
            webbrowser.open("http://localhost:8000")
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True, name="browser-opener").start()

    app = create_app(state)

    detection_mode = (
        "IsolationForest + Z-score (full ML mode)"
        if SKLEARN_AVAILABLE else
        "Z-score only (install sklearn for IsolationForest)"
    )
    fault_mode = (
        "DEMO — 7 scenarios × 45s gaps, starting in 30s"
        if demo_mode else
        "Auto random injection begins in ~90 seconds"
    )
    print(
        "\n" + "-" * 68 + "\n"
        f"  FCT AI Challenge: http://localhost:8000\n\n"
        f"  Services monitored: 7 FCT business-critical services\n"
        f"  Anomaly detection:  {detection_mode}\n"
        f"  RCA engine:         NetworkX dependency graph traversal\n"
        f"  Compliance:         FINTRAC fraud coverage monitoring active\n"
        f"  Fault injection:    {fault_mode}\n\n"
        f"  Press Ctrl+C to stop.\n"
        + "-" * 68 + "\n"
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
