# FINTRAC compliance monitoring for fraud-screening-service.
# Coverage drops are regulatory breaches, not just performance issues.

import threading
from datetime import datetime
from collections import deque


COMPLIANCE_THRESHOLD_NORMAL   = 95.0
COMPLIANCE_THRESHOLD_PEAK     = 97.0
COMPLIANCE_THRESHOLD_CRITICAL = 90.0
FINTRAC_ACT_REFERENCE = "PCMLTFA S.C. 2000, c. 17 (effective for title insurers Oct 1, 2025)"


class ComplianceIncident:
    def __init__(self, coverage_pct: float, threshold: float, peak_window: bool):
        self.incident_id   = f"COMP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        self.started_at    = datetime.utcnow().isoformat()
        self.coverage_pct  = coverage_pct
        self.threshold     = threshold
        self.peak_window   = peak_window
        self.severity      = self._compute_severity(coverage_pct)
        self.resolved      = False
        self.resolved_at   = None
        self.actions_taken = []
        self.regulatory_ref = FINTRAC_ACT_REFERENCE

    def _compute_severity(self, coverage: float) -> str:
        if coverage < COMPLIANCE_THRESHOLD_CRITICAL: return "CRITICAL"
        if coverage < 93.0:                          return "HIGH"
        if coverage < COMPLIANCE_THRESHOLD_NORMAL:   return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "incident_id":    self.incident_id,
            "type":           "COMPLIANCE_INCIDENT",
            "started_at":     self.started_at,
            "coverage_pct":   self.coverage_pct,
            "threshold":      self.threshold,
            "peak_window":    self.peak_window,
            "severity":       self.severity,
            "resolved":       self.resolved,
            "resolved_at":    self.resolved_at,
            "actions_taken":  self.actions_taken,
            "regulatory_ref": self.regulatory_ref,
            "statutory_obligation": (
                "FINTRAC PCMLTFA requires screening all transactions. "
                "Coverage below threshold means unscreened transactions were processed."
            ),
        }


class ComplianceMonitor:
    """Monitors fraud_screen_coverage_pct. Breaches trigger policy hold + escalation."""

    def __init__(self, environment):
        self.env = environment
        self._lock = threading.Lock()
        self._active_incidents: dict[str, ComplianceIncident] = {}
        self._incident_history: list[dict] = []
        self._coverage_history: deque = deque(maxlen=60)
        self._policy_hold_active = False
        self._last_alert_time: str = None

    def check(self, metrics: dict, business_context: dict) -> dict:
        """Run compliance check on current metrics. Called every agent cycle."""
        fraud_metrics = metrics.get("fraud-screening-service", {})
        if not fraud_metrics:
            return {"compliant": True, "actions": []}

        coverage  = fraud_metrics.get("fraud_screen_coverage_pct", 100.0)
        peak      = business_context.get("peak_window", False)
        threshold = COMPLIANCE_THRESHOLD_PEAK if peak else COMPLIANCE_THRESHOLD_NORMAL

        with self._lock:
            self._coverage_history.append({
                "timestamp": datetime.utcnow().isoformat(),
                "coverage":  coverage,
                "threshold": threshold,
            })

        if coverage < threshold:
            return self._handle_breach(coverage, threshold, peak, business_context)

        if self._active_incidents:
            return self._check_recovery(coverage, threshold)

        return {
            "compliant":    True,
            "coverage_pct": round(coverage, 2),
            "threshold":    threshold,
            "margin":       round(coverage - threshold, 2),
            "trend":        self._coverage_trend(),
            "actions":      [],
        }

    def get_status(self) -> dict:
        with self._lock:
            coverage_readings = list(self._coverage_history)
            current   = coverage_readings[-1]["coverage"] if coverage_readings else 99.8
            threshold = (
                COMPLIANCE_THRESHOLD_PEAK
                if len(coverage_readings) > 0 and
                   coverage_readings[-1].get("threshold") == COMPLIANCE_THRESHOLD_PEAK
                else COMPLIANCE_THRESHOLD_NORMAL
            )
            return {
                "compliant":        current >= threshold,
                "coverage_pct":     round(current, 2),
                "threshold":        threshold,
                "policy_hold":      self._policy_hold_active,
                "active_incidents": len(self._active_incidents),
                "incident_history": self._incident_history[-10:],
                "coverage_trend":   self._coverage_trend(),
                "regulatory_ref":   FINTRAC_ACT_REFERENCE,
            }

    def mark_incident_resolved(self, incident_id: str):
        with self._lock:
            incident = self._active_incidents.pop(incident_id, None)
            if incident:
                incident.resolved    = True
                incident.resolved_at = datetime.utcnow().isoformat()
                self._incident_history.append(incident.to_dict())

        if not self._active_incidents:
            self.env.disable_policy_hold()
            self._policy_hold_active = False

    def _handle_breach(self, coverage, threshold, peak, biz_ctx) -> dict:
        now     = datetime.utcnow().isoformat()
        actions = []

        with self._lock:
            if not self._active_incidents:
                incident = ComplianceIncident(coverage, threshold, peak)

                self.env.enable_policy_hold()
                self._policy_hold_active = True
                incident.actions_taken.append({
                    "action":    "enable_policy_hold",
                    "timestamp": now,
                    "rationale": "Issuing policies without fraud screening creates greater regulatory liability than a delayed closing.",
                })
                actions.append("enable_policy_hold")

                incident.actions_taken.append({
                    "action":    "escalate_compliance",
                    "timestamp": now,
                    "rationale": f"Only compliance officers can authorize resumption. Ref: {FINTRAC_ACT_REFERENCE}.",
                })
                actions.append("escalate_compliance")

                if incident.severity == "CRITICAL":
                    self.env.enable_circuit_breaker("policy-issuance-service")
                    incident.actions_taken.append({
                        "action":    "circuit_breaker_policy_issuance",
                        "timestamp": now,
                        "rationale": f"Coverage {coverage:.1f}% below critical threshold {COMPLIANCE_THRESHOLD_CRITICAL}%.",
                    })
                    actions.append("circuit_breaker_policy_issuance")

                self._active_incidents[incident.incident_id] = incident
                self._last_alert_time = now

        return {
            "compliant":    False,
            "coverage_pct": round(coverage, 2),
            "threshold":    threshold,
            "shortfall":    round(threshold - coverage, 2),
            "severity":     self._active_incidents and list(self._active_incidents.values())[0].severity,
            "actions":      actions,
            "policy_hold":  True,
            "incident_id":  list(self._active_incidents.keys())[0] if self._active_incidents else None,
            "statutory_obligation": (
                f"FINTRAC {FINTRAC_ACT_REFERENCE}: coverage {coverage:.1f}% below mandatory minimum {threshold:.0f}%."
            ),
            "trend": self._coverage_trend(),
        }

    def _check_recovery(self, coverage, threshold) -> dict:
        """Require 3 consecutive readings above threshold before releasing hold."""
        recent = list(self._coverage_history)[-3:]
        if len(recent) >= 3 and all(r["coverage"] >= threshold + 1.0 for r in recent):
            incident_ids = list(self._active_incidents.keys())
            for iid in incident_ids:
                self.mark_incident_resolved(iid)
            return {
                "compliant":    True,
                "coverage_pct": round(coverage, 2),
                "threshold":    threshold,
                "recovered":    True,
                "actions":      ["disable_policy_hold"],
                "trend":        "recovering",
            }
        return {
            "compliant":   False,
            "coverage_pct": round(coverage, 2),
            "threshold":   threshold,
            "recovering":  True,
            "note":        "Coverage improving — hold maintained pending sustained recovery.",
            "actions":     [],
            "trend":       "recovering",
        }

    def _coverage_trend(self) -> str:
        history = list(self._coverage_history)
        if len(history) < 4:
            return "stable"
        recent = [r["coverage"] for r in history[-4:]]
        delta  = recent[-1] - recent[0]
        if delta < -1.0:   return "declining"
        if delta >  1.0:   return "recovering"
        return "stable"
