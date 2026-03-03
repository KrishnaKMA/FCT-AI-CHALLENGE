# 7 FCT-specific fault scenarios — each reflects a real operational risk.

import time
import random
import threading
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class ActiveFault:
    scenario_id:       str
    name:              str
    started_at:        float
    duration_seconds:  float
    affected_services: list
    description:       str
    fct_impact:        str
    modifications:     dict
    auto_resolved:     bool = False
    resolved_at:       float = None


class FaultInjector:
    """Manages injection and removal of FCT-specific fault scenarios."""

    def __init__(self, environment):
        self.env = environment
        self._lock = threading.Lock()
        self._active_faults: dict[str, ActiveFault] = {}
        self._fault_history: list[dict] = []
        self._running = False

    def inject(self, scenario_id: str) -> dict:
        scenario_fn = SCENARIOS.get(scenario_id)
        if not scenario_fn:
            return {"error": f"Unknown scenario: {scenario_id}"}

        fault = scenario_fn()
        with self._lock:
            if scenario_id in self._active_faults:
                self._remove_fault(scenario_id)
            self._active_faults[scenario_id] = fault

        self._apply_fault(fault)

        return {
            "scenario_id":       scenario_id,
            "name":              fault.name,
            "affected_services": fault.affected_services,
            "duration_seconds":  fault.duration_seconds,
            "fct_impact":        fault.fct_impact,
            "injected_at":       datetime.utcnow().isoformat(),
        }

    def tick(self):
        """Update time-evolving faults and remove expired ones."""
        now       = time.monotonic()
        to_remove = []

        with self._lock:
            for sid, fault in self._active_faults.items():
                elapsed = now - fault.started_at

                if hasattr(fault, "_tick_fn") and fault._tick_fn:
                    mods = fault._tick_fn(elapsed)
                    for svc, mod in mods.items():
                        self.env.apply_fault(svc, mod)

                if elapsed >= fault.duration_seconds:
                    to_remove.append(sid)
                    fault.auto_resolved = True
                    fault.resolved_at   = now
                    self._fault_history.append({
                        "scenario_id":    sid,
                        "name":           fault.name,
                        "duration_actual": elapsed,
                        "resolved":       True,
                    })

        for sid in to_remove:
            self._remove_fault(sid)

    def get_active_faults(self) -> list:
        with self._lock:
            now = time.monotonic()
            return [
                {
                    "scenario_id":       sid,
                    "name":              f.name,
                    "elapsed_seconds":   round(now - f.started_at, 1),
                    "duration_seconds":  f.duration_seconds,
                    "affected_services": f.affected_services,
                    "fct_impact":        f.fct_impact,
                }
                for sid, f in self._active_faults.items()
            ]

    def resolve(self, scenario_id: str):
        self._remove_fault(scenario_id)

    def resolve_all(self):
        """Resolve every active fault — used by demo mode between scenarios."""
        with self._lock:
            ids = list(self._active_faults.keys())
        for scenario_id in ids:
            self._remove_fault(scenario_id)

    def _apply_fault(self, fault: ActiveFault):
        for svc, mods in fault.modifications.items():
            self.env.apply_fault(svc, mods)

    def _remove_fault(self, scenario_id: str):
        fault = self._active_faults.pop(scenario_id, None)
        if fault:
            for svc in fault.affected_services:
                self.env.clear_fault(svc)


# Scenario definitions

def _scenario_end_of_month_surge() -> ActiveFault:
    # 4x transaction spike on mortgage-processing and policy-issuance — LOAD_SURGE
    mods = {
        "mortgage-processing-service": {
            "request_rate":   {"type": "multiply", "value": 4.2},
            "queue_depth":    {"type": "multiply", "value": 4.0},
            "latency_p99_ms": {"type": "multiply", "value": 2.8},
            "cpu_percent":    {"type": "multiply", "value": 1.7},
            "error_rate":     {"type": "multiply", "value": 2.5},
        },
        "policy-issuance-service": {
            "request_rate":   {"type": "multiply", "value": 4.0},
            "queue_depth":    {"type": "multiply", "value": 3.8},
            "latency_p99_ms": {"type": "multiply", "value": 2.5},
            "cpu_percent":    {"type": "multiply", "value": 1.6},
        },
    }
    return ActiveFault(
        scenario_id="end_of_month_surge",
        name="End-of-Month Closing Surge",
        started_at=time.monotonic(),
        duration_seconds=180,
        affected_services=["mortgage-processing-service", "policy-issuance-service"],
        description="Transaction volume spike 4x normal. Queues building. Closing deadline SLAs at risk.",
        fct_impact="Multiple closing deadlines at risk. Lender SLAs breached. Revenue impact if not resolved.",
        modifications=mods,
    )


def _scenario_fraud_screening_degradation() -> ActiveFault:
    # Memory leak — coverage drifts below 95% FINTRAC floor — COMPLIANCE_INCIDENT
    def tick_fn(elapsed: float) -> dict:
        drift = min(elapsed / 120.0, 1.0)
        return {
            "fraud-screening-service": {
                "memory_percent":            {"type": "add",      "value": 25.0 * drift},
                "latency_p99_ms":            {"type": "multiply", "value": 1.0 + 4.0 * drift},
                "fraud_screen_coverage_pct": {"type": "add",      "value": -12.0 * drift},
                "error_rate":                {"type": "multiply", "value": 1.0 + 8.0 * drift},
            }
        }

    fault = ActiveFault(
        scenario_id="fraud_screening_degradation",
        name="Fraud Screening Service Degradation",
        started_at=time.monotonic(),
        duration_seconds=240,
        affected_services=["fraud-screening-service"],
        description="Memory leak causing coverage degradation. FINTRAC compliance breach imminent.",
        fct_impact="COMPLIANCE INCIDENT: fraud_screen_coverage_pct dropping below 95% threshold. "
                   "Policy issuance must be halted until service is restored.",
        modifications={
            "fraud-screening-service": {
                "memory_percent":            {"type": "add",      "value": 5.0},
                "latency_p99_ms":            {"type": "multiply", "value": 1.2},
                "fraud_screen_coverage_pct": {"type": "add",      "value": -3.0},
            }
        },
    )
    fault._tick_fn = tick_fn
    return fault


def _scenario_title_search_timeout() -> ActiveFault:
    # Land registry API unresponsive — cascades to policy-issuance — EXTERNAL_DEPENDENCY
    mods = {
        "title-search-service": {
            "latency_p99_ms": {"type": "multiply", "value": 15.0},
            "error_rate":     {"type": "multiply", "value": 20.0},
            "queue_depth":    {"type": "multiply", "value": 8.0},
        },
        "policy-issuance-service": {
            "queue_depth":    {"type": "multiply", "value": 3.0},
            "latency_p99_ms": {"type": "multiply", "value": 2.5},
            "error_rate":     {"type": "multiply", "value": 4.0},
        },
    }
    return ActiveFault(
        scenario_id="title_search_timeout",
        name="Title Search External API Timeout",
        started_at=time.monotonic(),
        duration_seconds=150,
        affected_services=["title-search-service", "policy-issuance-service"],
        description="Land registry API unresponsive. Title search timing out.",
        fct_impact="Policy issuance blocked. No title search = no policy. Lawyers and lenders cannot complete transactions.",
        modifications=mods,
    )


def _scenario_identity_verification_bottleneck() -> ActiveFault:
    # KYC queue saturated — INFRASTRUCTURE_FAILURE
    mods = {
        "identity-verification-service": {
            "queue_depth":    {"type": "multiply", "value": 6.0},
            "latency_p99_ms": {"type": "multiply", "value": 4.0},
            "cpu_percent":    {"type": "multiply", "value": 1.8},
            "error_rate":     {"type": "multiply", "value": 3.0},
        },
    }
    return ActiveFault(
        scenario_id="identity_verification_bottleneck",
        name="Identity Verification Bottleneck",
        started_at=time.monotonic(),
        duration_seconds=160,
        affected_services=["identity-verification-service"],
        description="KYC/AML queue saturated. Biometric verification processing overwhelmed.",
        fct_impact="43,000 legal professionals waiting for KYC clearance. Closing deadlines at risk.",
        modifications=mods,
    )


def _scenario_document_vault_disk_saturation() -> ActiveFault:
    # Storage fills up — STORAGE_SATURATION (ops must provision disk, agent can only alert)
    def tick_fn(elapsed: float) -> dict:
        drift = min(elapsed / 90.0, 1.0)
        return {
            "document-vault-service": {
                "disk_usage_pct": {"type": "add",      "value": 30.0 * drift},
                "error_rate":     {"type": "multiply", "value": 1.0 + 15.0 * drift},
                "latency_p99_ms": {"type": "multiply", "value": 1.0 + 5.0 * drift},
            }
        }

    fault = ActiveFault(
        scenario_id="document_vault_disk_saturation",
        name="Document Vault Disk Saturation",
        started_at=time.monotonic(),
        duration_seconds=200,
        affected_services=["document-vault-service"],
        description="Document vault storage saturating. Write operations failing.",
        fct_impact="43,000 legal professionals cannot upload closing documents. Closings blocked.",
        modifications={
            "document-vault-service": {
                "disk_usage_pct": {"type": "add",      "value": 10.0},
                "error_rate":     {"type": "multiply", "value": 2.0},
            }
        },
    )
    fault._tick_fn = tick_fn
    return fault


def _scenario_suspicious_transaction_velocity() -> ActiveFault:
    # Coordinated spike across fraud-screening + property-intelligence — FRAUD_SIGNAL
    mods = {
        "fraud-screening-service": {
            "request_rate":              {"type": "multiply", "value": 3.5},
            "cpu_percent":               {"type": "multiply", "value": 1.6},
            "queue_depth":               {"type": "multiply", "value": 4.0},
            "fraud_screen_coverage_pct": {"type": "add",      "value": 0.0},
        },
        "property-intelligence-api": {
            "request_rate":   {"type": "multiply", "value": 4.0},
            "latency_p99_ms": {"type": "multiply", "value": 1.3},
        },
    }
    fault = ActiveFault(
        scenario_id="suspicious_transaction_velocity",
        name="Suspicious Transaction Velocity — Potential Fraud Pattern",
        started_at=time.monotonic(),
        duration_seconds=120,
        affected_services=["fraud-screening-service", "property-intelligence-api"],
        description="Abnormal transaction volume spike with geographic concentration. Classic mortgage fraud velocity pattern.",
        fct_impact="FRAUD SIGNAL: Coordinated transaction cluster detected. FCT Fraud Insights Centre protocol triggered.",
        modifications=mods,
    )
    fault.fraud_signal = True
    return fault


def _scenario_cascading_policy_failure() -> ActiveFault:
    # title-search fails → policy-issuance → mortgage-processing — CASCADE
    mods = {
        "title-search-service": {
            "error_rate":     {"type": "multiply", "value": 25.0},
            "latency_p99_ms": {"type": "multiply", "value": 8.0},
            "cpu_percent":    {"type": "multiply", "value": 1.9},
        },
        "policy-issuance-service": {
            "error_rate":     {"type": "multiply", "value": 8.0},
            "queue_depth":    {"type": "multiply", "value": 5.0},
            "latency_p99_ms": {"type": "multiply", "value": 4.0},
        },
        "mortgage-processing-service": {
            "queue_depth":    {"type": "multiply", "value": 3.5},
            "latency_p99_ms": {"type": "multiply", "value": 2.5},
            "error_rate":     {"type": "multiply", "value": 3.0},
        },
    }
    return ActiveFault(
        scenario_id="cascading_policy_failure",
        name="Cascading Policy Issuance Failure",
        started_at=time.monotonic(),
        duration_seconds=200,
        affected_services=[
            "title-search-service",
            "policy-issuance-service",
            "mortgage-processing-service",
        ],
        description="title-search failure cascading through policy-issuance to mortgage-processing.",
        fct_impact="CRITICAL: Full closing pipeline degraded. 450 lenders affected. Multiple closings at risk.",
        modifications=mods,
    )


SCENARIOS = {
    "end_of_month_surge":               _scenario_end_of_month_surge,
    "fraud_screening_degradation":      _scenario_fraud_screening_degradation,
    "title_search_timeout":             _scenario_title_search_timeout,
    "identity_verification_bottleneck": _scenario_identity_verification_bottleneck,
    "document_vault_disk_saturation":   _scenario_document_vault_disk_saturation,
    "suspicious_transaction_velocity":  _scenario_suspicious_transaction_velocity,
    "cascading_policy_failure":         _scenario_cascading_policy_failure,
}

SCENARIO_DESCRIPTIONS = {
    sid: SCENARIOS[sid]().description
    for sid in SCENARIOS
}
