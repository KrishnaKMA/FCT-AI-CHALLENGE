# Outcome tracking and confidence calibration for the agent's remediation actions.

import threading
import sqlite3
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path


DB_PATH = Path(__file__).parent.parent / "data" / "sentinel.db"

RESOLUTION_CHECK_DELAY_SECONDS    = 60   # prod: 300
RESOLUTION_IMPROVEMENT_THRESHOLD  = 0.4
CLOSINGS_PROTECTED_PER_MINUTE_AVOIDED = 4.0


class FeedbackLoop:
    """Tracks outcomes of remediation actions and adjusts confidence thresholds."""

    def __init__(self, state, environment):
        self.state = state
        self.env   = environment
        self._lock = threading.Lock()
        self._pending: dict = {}
        self._success_rates: dict = defaultdict(list)
        self._confidence_adjustments: dict = defaultdict(float)

    def register_decision(self, decision: dict, pre_anomaly_scores: dict):
        check_after = (
            datetime.utcnow() + timedelta(seconds=RESOLUTION_CHECK_DELAY_SECONDS)
        ).isoformat()
        with self._lock:
            self._pending[decision["incident_id"]] = {
                "decision":    decision,
                "check_after": check_after,
                "pre_scores":  pre_anomaly_scores,
                "checked":     False,
            }

    def check_outcomes(self, current_metrics: dict, current_anomalies: list):
        now = datetime.utcnow()
        resolved_ids = []

        with self._lock:
            pending_copy = dict(self._pending)

        for iid, entry in pending_copy.items():
            if entry["checked"]:
                continue
            check_time = datetime.fromisoformat(entry["check_after"])
            if now < check_time:
                continue
            outcome = self._assess_outcome(entry["decision"], entry["pre_scores"], current_anomalies)
            self._record_outcome(entry["decision"], outcome)
            resolved_ids.append(iid)

        with self._lock:
            for iid in resolved_ids:
                entry = self._pending.get(iid, {})
                if entry:
                    entry["checked"] = True

    def get_confidence_adjustment(self, action_type: str) -> float:
        return self._confidence_adjustments.get(action_type, 0.0)

    def get_performance_summary(self) -> dict:
        with self._lock:
            total_decisions = sum(len(v) for v in self._success_rates.values())
            total_successes = sum(sum(v) for v in self._success_rates.values())
            per_action = {}
            for (action, atype), outcomes in self._success_rates.items():
                key = f"{action}:{atype}"
                per_action[key] = {
                    "action":       action,
                    "anomaly_type": atype,
                    "success_rate": round(sum(outcomes) / len(outcomes), 3) if outcomes else 0,
                    "n_samples":    len(outcomes),
                }
            return {
                "total_decisions":       total_decisions,
                "overall_success_rate":  (
                    round(total_successes / total_decisions, 3) if total_decisions > 0 else 0.0
                ),
                "per_action_rates":      list(per_action.values()),
                "pending_checks":        len(self._pending),
                "confidence_adjustments": dict(self._confidence_adjustments),
            }

    def _assess_outcome(self, decision: dict, pre_scores: dict, current_anomalies: list) -> str:
        root = decision.get("rca_result", {}).get("root_cause")
        if not root or root in ("FRAUD_VELOCITY_PATTERN",):
            return "ESCALATED"

        still_anomalous = any(a.get("service") == root for a in current_anomalies)

        if not still_anomalous:
            return "RESOLVED"

        current_score = next(
            (a.get("confidence", 0) for a in current_anomalies if a.get("service") == root),
            0.0,
        )
        pre_score = pre_scores.get(root, 0.0)

        if current_score < pre_score * 0.6:
            return "PARTIAL"

        return "ESCALATED"

    def _record_outcome(self, decision: dict, outcome: str):
        success    = outcome == "RESOLVED"
        partial    = outcome == "PARTIAL"
        actions    = decision.get("actions_taken", [])
        atype      = decision.get("incident_type", "UNKNOWN")
        incident_id = decision.get("incident_id", "")
        autonomous = decision.get("autonomous", False)

        with self._lock:
            for action in actions:
                key = (action, atype)
                self._success_rates[key].append(1 if success else (0.5 if partial else 0))
                recent = self._success_rates[key][-10:]
                rate   = sum(recent) / len(recent) if recent else 0.5
                if rate > 0.8:
                    self._confidence_adjustments[action] = min(0.1, self._confidence_adjustments[action] + 0.01)
                elif rate < 0.6:
                    self._confidence_adjustments[action] = max(-0.1, self._confidence_adjustments[action] - 0.01)

        with self._lock:
            if success:
                self.state.counters["incidents_auto_resolved"] += 1
                # transactions_at_risk/min × 3 min of downtime prevented
                biz_ctx = decision.get("business_context", {})
                at_risk_per_min = biz_ctx.get("active_transactions_at_risk", 0)
                rate    = at_risk_per_min if at_risk_per_min > 0 else CLOSINGS_PROTECTED_PER_MINUTE_AVOIDED
                closings = round(rate * 3.0)
                self.state.counters["estimated_closings_protected"] += closings
            elif not autonomous:
                self.state.counters["incidents_escalated"] += 1

        self._update_decision_outcome(incident_id, outcome)

        with self._lock:
            for entry in self.state.activity_log:
                if entry.get("incident_id") == incident_id:
                    entry["outcome"] = outcome
                    entry["outcome_resolved_at"] = datetime.utcnow().isoformat()
                    break

    def _update_decision_outcome(self, incident_id: str, outcome: str):
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute(
                "UPDATE incidents SET outcome = ? WHERE id = ?",
                (outcome, incident_id),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
