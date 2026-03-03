# FCT-aware remediation engine: maps (service, anomaly_type, confidence) → action.

import uuid
import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path


DB_PATH = Path(__file__).parent.parent / "data" / "sentinel.db"

FCT_VALUES = {
    "scale_up_pods":            "Act like an owner — agent scaled pods without waiting for human approval",
    "pre_scale_pods":           "Take intelligent risks — proactively scaled before the surge hit",
    "enable_policy_hold":       "Act like an owner — decisive action taken; regulatory risk > delay risk",
    "escalate_compliance":      "Act like an owner — compliance obligations are non-negotiable",
    "activate_cached_fallback": "Solve problems — activated fallback to maintain service continuity",
    "restart_service":          "Solve problems — autonomous restart applied to restore service health",
    "enable_circuit_breaker":   "Act like an owner — isolated the fault to protect downstream services",
    "flag_fraud_pattern":       "Act like an owner — escalated potential fraud immediately",
    "page_fraud_team":          "Solve problems — routed to the right team, not ops",
    "page_oncall":              "Take intelligent risks — confidence below threshold; human judgment required",
    "recommend_only":           "Take intelligent risks — confidence below action threshold; recommending only",
    "scale_down_pods":          "Act like an owner — efficient resource management after incident resolved",
    "disable_circuit_breaker":  "Solve problems — service recovered; circuit breaker released",
}

SCALE_UP_AMOUNT   = 2
SCALE_DOWN_AMOUNT = 1
MAX_PODS          = 12
BASE_PODS = {
    "policy-issuance-service":       4,
    "fraud-screening-service":       6,
    "title-search-service":          3,
    "identity-verification-service": 5,
    "mortgage-processing-service":   3,
    "document-vault-service":        4,
    "property-intelligence-api":     4,
}

AUTONOMOUS_THRESHOLD = 0.80
RECOMMEND_THRESHOLD  = 0.60

# Prevent same incident type from spamming the feed while a fault is still active
INCIDENT_COOLDOWN_SECS   = 40
COMPLIANCE_COOLDOWN_SECS = 90


class RemediationEngine:
    """FCT-aware autonomous remediation: decide, execute, and log every action."""

    def __init__(self, environment, state):
        self.env   = environment
        self.state = state
        self._lock = threading.Lock()
        self._current_pods = dict(BASE_PODS)
        self._incident_cooldown: dict = {}  # {anomaly_type: last_fire_epoch}
        self._init_db()

    def decide_and_act(
        self,
        rca_result:        dict,
        compliance_status: dict,
        business_context:  dict,
        anomalies:         list,
    ) -> dict:
        if not rca_result.get("root_cause"):
            return None

        # Cooldown: don't fire the same incident type repeatedly while fault is still active
        import time as _time
        anomaly_type = rca_result.get("anomaly_type", "UNKNOWN")
        cooldown = COMPLIANCE_COOLDOWN_SECS if anomaly_type == "COMPLIANCE_INCIDENT" else INCIDENT_COOLDOWN_SECS
        last_fire = self._incident_cooldown.get(anomaly_type, 0)
        if (_time.time() - last_fire) < cooldown:
            return None
        self._incident_cooldown[anomaly_type] = _time.time()

        incident_id = f"INC-{self._next_incident_num():04d}"
        actions, autonomous = self._select_actions(rca_result, compliance_status, business_context)

        if not actions:
            return None

        execution_results = [
            self._execute_action(action, rca_result, business_context, autonomous)
            for action in actions
        ]

        at_risk  = business_context.get("active_transactions_at_risk", 0)
        decision = {
            "timestamp":    datetime.utcnow().isoformat(),
            "incident_id":  incident_id,
            "incident_type": rca_result.get("anomaly_type", "UNKNOWN"),
            "business_context": {
                "closing_day":               business_context.get("closing_day", False),
                "peak_window":               business_context.get("peak_window", False),
                "active_transactions_at_risk": at_risk,
                "intensity":                 business_context.get("intensity", 1.0),
            },
            "anomalies_detected": [
                {
                    "service":   a.get("service"),
                    "metric":    a.get("details", [{}])[0].get("metric", "multiple"),
                    "value":     a.get("details", [{}])[0].get("value", 0),
                    "threshold": a.get("details", [{}])[0].get("threshold", None),
                    "score":     a.get("confidence", 0),
                }
                for a in anomalies[:3]
            ],
            "rca_result": {
                "root_cause":     rca_result.get("root_cause"),
                "confidence":     rca_result.get("confidence"),
                "reasoning":      rca_result.get("reasoning"),
                "regulatory_risk": rca_result.get("regulatory_risk", False),
            },
            "actions_taken":      actions,
            "execution_results":  execution_results,
            "autonomous":         autonomous,
            "fct_value_applied":  FCT_VALUES.get(actions[0], "Solve problems"),
            "outcome":            "pending",
            "outcome_resolved_at": None,
        }

        self._persist_decision(decision)
        with self._lock:
            self.state.activity_log.append(decision)
            if len(self.state.activity_log) > 200:
                self.state.activity_log = self.state.activity_log[-200:]
            if not autonomous:
                self.state.counters["incidents_escalated"] += 1

        return decision

    def prescale_for_upcoming_peak(self, business_context: dict) -> dict:
        """Pre-scale pods when a peak window is predicted within 30 minutes."""
        if not self.state.autonomous_mode:
            return None
        if not business_context.get("pre_scale_recommended"):
            return None
        if getattr(self.state, "_prescale_done", False):
            return None

        actions_taken = []
        for svc in ["policy-issuance-service", "mortgage-processing-service",
                    "fraud-screening-service", "identity-verification-service"]:
            target = min(MAX_PODS, BASE_PODS[svc] + SCALE_UP_AMOUNT)
            self.env.scale_pods(svc, target)
            self._current_pods[svc] = target
            actions_taken.append(f"scale_pods({svc}, {target})")

        decision = {
            "timestamp":         datetime.utcnow().isoformat(),
            "incident_id":       f"PRE-{self._next_incident_num():04d}",
            "incident_type":     "PROACTIVE_PRESCALE",
            "business_context":  business_context,
            "anomalies_detected": [],
            "rca_result":        {"root_cause": "PREDICTED_PEAK", "confidence": 0.90},
            "actions_taken":     ["pre_scale_pods"] + actions_taken,
            "autonomous":        True,
            "fct_value_applied": FCT_VALUES["pre_scale_pods"],
            "outcome":           "pending",
            "outcome_resolved_at": None,
        }

        self._persist_decision(decision)
        with self._lock:
            self.state.activity_log.append(decision)
            self.state._prescale_done = True

        return decision

    def post_incident_cleanup(self, resolved_services: list):
        for svc in resolved_services:
            base    = BASE_PODS.get(svc, 4)
            current = self._current_pods.get(svc, base)
            if current > base:
                target = max(base, current - SCALE_DOWN_AMOUNT)
                self.env.scale_pods(svc, target)
                self._current_pods[svc] = target
                self.env.disable_circuit_breaker(svc)
                self.env.disable_cached_fallback(svc)

    def _select_actions(self, rca, compliance, biz_ctx) -> tuple[list, bool]:
        anomaly_type = rca.get("anomaly_type")
        confidence   = rca.get("confidence", 0.0)
        autonomous   = self.state.autonomous_mode and confidence >= AUTONOMOUS_THRESHOLD

        if anomaly_type == "COMPLIANCE_INCIDENT" or (compliance and not compliance.get("compliant")):
            return ["enable_policy_hold", "escalate_compliance"], True

        if anomaly_type == "FRAUD_SIGNAL":
            return ["flag_fraud_pattern", "page_fraud_team"], True

        if anomaly_type == "STORAGE_SATURATION":
            return ["page_oncall"], False

        if confidence < RECOMMEND_THRESHOLD:
            return [], False

        if confidence < AUTONOMOUS_THRESHOLD:
            return ["recommend_only", "page_oncall"], False

        if anomaly_type == "LOAD_SURGE":
            return ["scale_up_pods"], autonomous

        if anomaly_type == "EXTERNAL_DEPENDENCY":
            return ["activate_cached_fallback", "scale_up_pods"], autonomous

        if anomaly_type == "CASCADE":
            return ["enable_circuit_breaker", "scale_up_pods"], autonomous

        if anomaly_type == "INFRASTRUCTURE_FAILURE":
            return ["restart_service"], autonomous

        return ["recommend_only", "page_oncall"], False

    def _execute_action(self, action: str, rca: dict, biz_ctx: dict, autonomous: bool) -> dict:
        root   = rca.get("root_cause", "unknown")
        result = {"action": action, "executed": autonomous, "target": root}

        if not autonomous:
            result["note"] = "Recommendation only — autonomous mode off or confidence below threshold"
            return result

        try:
            if action == "scale_up_pods" and root in BASE_PODS:
                current = self._current_pods.get(root, BASE_PODS[root])
                target  = min(MAX_PODS, current + SCALE_UP_AMOUNT)
                self.env.scale_pods(root, target)
                self._current_pods[root] = target
                result["pods_scaled_to"] = target

            elif action == "enable_policy_hold":
                self.env.enable_policy_hold()
                result["policy_hold"] = True

            elif action == "activate_cached_fallback":
                self.env.enable_cached_fallback(root)
                result["cached_fallback"] = True

            elif action == "enable_circuit_breaker":
                self.env.enable_circuit_breaker(root)
                result["circuit_breaker"] = True

            elif action == "restart_service":
                self.env.enable_circuit_breaker(root)
                import time; time.sleep(0.5)
                self.env.disable_circuit_breaker(root)
                result["restarted"] = True

            result["success"] = True

        except Exception as e:
            result["success"] = False
            result["error"]   = str(e)

        return result

    def _init_db(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                incident_id TEXT,
                data        TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id            TEXT PRIMARY KEY,
                timestamp     TEXT,
                incident_type TEXT,
                outcome       TEXT,
                data          TEXT
            )
        """)
        conn.commit()
        conn.close()
        self._incident_counter = self._load_incident_counter()

    def _persist_decision(self, decision: dict):
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                "INSERT INTO decisions (timestamp, incident_id, data) VALUES (?, ?, ?)",
                (decision["timestamp"], decision["incident_id"], json.dumps(decision)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO incidents (id, timestamp, incident_type, outcome, data) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    decision["incident_id"],
                    decision["timestamp"],
                    decision["incident_type"],
                    decision["outcome"],
                    json.dumps(decision),
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _load_incident_counter(self) -> int:
        try:
            conn = sqlite3.connect(str(DB_PATH))
            row  = conn.execute("SELECT COUNT(*) FROM decisions").fetchone()
            conn.close()
            return (row[0] if row else 0) + 1
        except Exception:
            return 1

    def _next_incident_num(self) -> int:
        with self._lock:
            n = self._incident_counter
            self._incident_counter += 1
            return n
