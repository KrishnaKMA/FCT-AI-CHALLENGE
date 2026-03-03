# Simulates FCT's 7 core microservices: metrics respond to the closing calendar,
# active fault scenarios, and remediation actions.

import time
import math
import random
import threading
from datetime import datetime
from collections import deque

from simulator.closing_calendar import ClosingCalendar


SERVICE_CONFIGS = {
    "policy-issuance-service": {
        "description": "Generates title insurance policies. Core revenue driver. SLA: 5 min per policy.",
        "base": {
            "cpu_percent":        42.0,
            "memory_percent":     54.0,
            "request_rate":       118.0,
            "error_rate":         0.4,
            "latency_p99_ms":     820.0,
            "queue_depth":        10.0,
            "pod_count":          4.0,
            "sla_compliance_pct": 99.1,
        },
        "noise_std": {
            "cpu_percent":        4.0,
            "memory_percent":     2.5,
            "request_rate":       12.0,
            "error_rate":         0.08,
            "latency_p99_ms":     60.0,
            "queue_depth":        2.0,
            "sla_compliance_pct": 0.2,
        },
        "peak_multipliers": {
            "request_rate":   4.0,
            "queue_depth":    3.5,
            "cpu_percent":    1.6,
            "latency_p99_ms": 1.8,
        },
        "sla_latency_ms":    300_000,
        "compliance_critical": False,
    },

    "fraud-screening-service": {
        "description": "Real-time ML fraud detection. FINTRAC regulated. Coverage must stay > 95%.",
        "base": {
            "cpu_percent":               68.0,
            "memory_percent":            62.0,
            "request_rate":              116.0,
            "error_rate":                0.15,
            "latency_p99_ms":            420.0,
            "queue_depth":               7.0,
            "pod_count":                 6.0,
            "fraud_screen_coverage_pct": 99.8,
            "sla_compliance_pct":        99.8,
        },
        "noise_std": {
            "cpu_percent":               5.0,
            "memory_percent":            2.0,
            "request_rate":              10.0,
            "error_rate":                0.05,
            "latency_p99_ms":            35.0,
            "queue_depth":               1.5,
            "fraud_screen_coverage_pct": 0.05,
            "sla_compliance_pct":        0.05,
        },
        "peak_multipliers": {
            "request_rate": 4.0,
            "cpu_percent":  1.4,
            "queue_depth":  2.0,
        },
        "sla_latency_ms":    2_000,
        "compliance_critical": True,
    },

    "title-search-service": {
        "description": "Queries land registry for property title history. External API dependency.",
        "base": {
            "cpu_percent":        35.0,
            "memory_percent":     48.0,
            "request_rate":       95.0,
            "error_rate":         0.6,
            "latency_p99_ms":     1_200.0,
            "queue_depth":        8.0,
            "pod_count":          3.0,
            "sla_compliance_pct": 98.5,
        },
        "noise_std": {
            "cpu_percent":        3.5,
            "memory_percent":     2.0,
            "request_rate":       10.0,
            "error_rate":         0.15,
            "latency_p99_ms":     150.0,
            "queue_depth":        2.0,
            "sla_compliance_pct": 0.3,
        },
        "peak_multipliers": {
            "request_rate":   3.5,
            "latency_p99_ms": 1.5,
            "queue_depth":    3.0,
        },
        "sla_latency_ms":    10_000,
        "compliance_critical": False,
    },

    "identity-verification-service": {
        "description": "KYC/AML biometric + document verification. FCT acquired Fintracker for this.",
        "base": {
            "cpu_percent":        55.0,
            "memory_percent":     60.0,
            "request_rate":       85.0,
            "error_rate":         0.3,
            "latency_p99_ms":     1_800.0,
            "queue_depth":        12.0,
            "pod_count":          5.0,
            "sla_compliance_pct": 98.8,
        },
        "noise_std": {
            "cpu_percent":        5.0,
            "memory_percent":     3.0,
            "request_rate":       8.0,
            "error_rate":         0.08,
            "latency_p99_ms":     200.0,
            "queue_depth":        3.0,
            "sla_compliance_pct": 0.25,
        },
        "peak_multipliers": {
            "request_rate":   3.0,
            "queue_depth":    4.0,
            "latency_p99_ms": 1.4,
        },
        "sla_latency_ms":    30_000,
        "compliance_critical": False,
    },

    "mortgage-processing-service": {
        "description": "Handles payout/discharge instructions. Serves 450 lenders. Failures block closings.",
        "base": {
            "cpu_percent":        38.0,
            "memory_percent":     50.0,
            "request_rate":       72.0,
            "error_rate":         0.25,
            "latency_p99_ms":     650.0,
            "queue_depth":        6.0,
            "pod_count":          3.0,
            "sla_compliance_pct": 99.3,
        },
        "noise_std": {
            "cpu_percent":        4.0,
            "memory_percent":     2.5,
            "request_rate":       8.0,
            "error_rate":         0.06,
            "latency_p99_ms":     70.0,
            "queue_depth":        2.0,
            "sla_compliance_pct": 0.2,
        },
        "peak_multipliers": {
            "request_rate":   4.0,
            "queue_depth":    3.5,
            "cpu_percent":    1.5,
            "latency_p99_ms": 2.0,
        },
        "sla_latency_ms":    60_000,
        "compliance_critical": False,
    },

    "document-vault-service": {
        "description": "Secure legal document storage/retrieval. Serves 43,000 legal professionals.",
        "base": {
            "cpu_percent":        28.0,
            "memory_percent":     72.0,
            "request_rate":       210.0,
            "error_rate":         0.2,
            "latency_p99_ms":     380.0,
            "queue_depth":        5.0,
            "pod_count":          4.0,
            "disk_usage_pct":     65.0,
            "sla_compliance_pct": 99.5,
        },
        "noise_std": {
            "cpu_percent":        3.0,
            "memory_percent":     2.0,
            "request_rate":       20.0,
            "error_rate":         0.05,
            "latency_p99_ms":     40.0,
            "queue_depth":        1.5,
            "disk_usage_pct":     0.5,
            "sla_compliance_pct": 0.1,
        },
        "peak_multipliers": {
            "request_rate": 2.5,
            "queue_depth":  2.0,
        },
        "sla_latency_ms":    5_000,
        "compliance_critical": False,
    },

    "property-intelligence-api": {
        "description": "External-facing bulk property data API. Used by lenders and analysts. 98% hit rate SLA.",
        "base": {
            "cpu_percent":        30.0,
            "memory_percent":     44.0,
            "request_rate":       340.0,
            "error_rate":         0.5,
            "latency_p99_ms":     290.0,
            "queue_depth":        3.0,
            "pod_count":          4.0,
            "cache_hit_rate_pct": 94.2,
            "sla_compliance_pct": 98.8,
        },
        "noise_std": {
            "cpu_percent":        4.0,
            "memory_percent":     2.0,
            "request_rate":       35.0,
            "error_rate":         0.1,
            "latency_p99_ms":     30.0,
            "queue_depth":        1.0,
            "cache_hit_rate_pct": 0.5,
            "sla_compliance_pct": 0.2,
        },
        "peak_multipliers": {
            "request_rate": 2.0,
            "cpu_percent":  1.3,
        },
        "sla_latency_ms":    1_000,
        "compliance_critical": False,
    },
}

METRIC_BOUNDS = {
    "cpu_percent":               (0.0, 100.0),
    "memory_percent":            (0.0, 100.0),
    "request_rate":              (0.0, 2000.0),
    "error_rate":                (0.0, 100.0),
    "latency_p99_ms":            (10.0, 120_000.0),
    "queue_depth":               (0.0, 500.0),
    "pod_count":                 (0.0, 20.0),
    "sla_compliance_pct":        (0.0, 100.0),
    "fraud_screen_coverage_pct": (0.0, 100.0),
    "disk_usage_pct":            (0.0, 100.0),
    "cache_hit_rate_pct":        (0.0, 100.0),
}


class FCTEnvironment:
    """Simulates FCT's 7-service environment with realistic, time-varying metrics."""

    def __init__(self, calendar: ClosingCalendar):
        self.calendar = calendar
        self._lock    = threading.Lock()

        self._state: dict[str, dict]      = {}
        self._fault_mods: dict[str, dict] = {}
        self._pod_overrides: dict[str, int] = {}
        self._circuit_breakers: set[str]  = set()
        self._policy_hold: bool           = False
        self._cached_fallbacks: set[str]  = set()

        self.metric_history: dict[str, deque] = {
            svc: deque(maxlen=120) for svc in SERVICE_CONFIGS
        }

        self.transactions_today       = 0
        self.policies_issued          = 0
        self.fraud_screens_completed  = 0
        self.start_time               = datetime.utcnow()

        for svc, cfg in SERVICE_CONFIGS.items():
            self._state[svc] = dict(cfg["base"])

    def tick(self) -> dict:
        """Advance simulation by one step. Call every 5 seconds."""
        biz_ctx   = self.calendar.get_context()
        intensity = biz_ctx["intensity"]
        ts        = datetime.utcnow().isoformat()

        with self._lock:
            snapshot = {}
            for svc, cfg in SERVICE_CONFIGS.items():
                metrics = self._compute_metrics(svc, cfg, intensity)
                self._state[svc] = metrics
                self.metric_history[svc].append({"timestamp": ts, "metrics": dict(metrics)})
                snapshot[svc] = dict(metrics)

            base_rate = biz_ctx["expected_request_rate"]
            if not self._policy_hold:
                self.transactions_today += int(base_rate * 5 / 60)
                self.policies_issued    += max(0, int(base_rate * 0.7 * 5 / 60))
            self.fraud_screens_completed += int(base_rate * 5 / 60)

        return snapshot

    def apply_fault(self, service: str, modifications: dict):
        with self._lock:
            self._fault_mods[service] = modifications

    def clear_fault(self, service: str):
        with self._lock:
            self._fault_mods.pop(service, None)

    def clear_all_faults(self):
        with self._lock:
            self._fault_mods.clear()

    def scale_pods(self, service: str, count: int):
        with self._lock:
            self._pod_overrides[service] = max(1, min(20, count))

    def enable_circuit_breaker(self, service: str):
        with self._lock:
            self._circuit_breakers.add(service)

    def disable_circuit_breaker(self, service: str):
        with self._lock:
            self._circuit_breakers.discard(service)

    def enable_policy_hold(self):
        with self._lock:
            self._policy_hold = True

    def disable_policy_hold(self):
        with self._lock:
            self._policy_hold = False

    def enable_cached_fallback(self, service: str):
        with self._lock:
            self._cached_fallbacks.add(service)

    def disable_cached_fallback(self, service: str):
        with self._lock:
            self._cached_fallbacks.discard(service)

    def get_current_metrics(self) -> dict:
        with self._lock:
            return {svc: dict(m) for svc, m in self._state.items()}

    def get_history(self, service: str, n: int = 30) -> list:
        with self._lock:
            history = list(self.metric_history[service])
            return history[-n:] if len(history) > n else history

    def _compute_metrics(self, svc: str, cfg: dict, intensity: float) -> dict:
        base    = cfg["base"]
        noise   = cfg["noise_std"]
        pmult   = cfg.get("peak_multipliers", {})
        fault   = self._fault_mods.get(svc, {})
        circuit = svc in self._circuit_breakers
        cached  = svc in self._cached_fallbacks

        base_pods = base["pod_count"]
        pod_count = self._pod_overrides.get(svc, base_pods)
        scale_factor = base_pods / max(pod_count, 1)

        metrics = {}
        for metric, base_val in base.items():
            if metric == "pod_count":
                metrics["pod_count"] = pod_count
                continue

            val = base_val

            if metric in pmult and intensity > 1.0:
                val = val * (1.0 + (pmult[metric] - 1.0) * (intensity - 1.0) / 3.0)

            if metric in ("latency_p99_ms", "queue_depth", "error_rate"):
                val = val * max(0.3, scale_factor)
            elif metric == "cpu_percent":
                val = val * max(0.3, scale_factor)

            if circuit and metric in ("request_rate", "queue_depth"):
                val = val * 0.1

            if cached and metric == "latency_p99_ms":
                val = val * 0.2

            if metric in fault:
                fmod = fault[metric]
                if isinstance(fmod, dict):
                    if   fmod.get("type") == "multiply": val = val * fmod["value"]
                    elif fmod.get("type") == "add":      val = val + fmod["value"]
                    elif fmod.get("type") == "set":      val = fmod["value"]
                    elif fmod.get("type") == "drift":
                        elapsed = fmod.get("elapsed_seconds", 0)
                        val = val + fmod["rate"] * elapsed
                else:
                    val = val * fmod

            std = noise.get(metric, 0.0)
            val = val + random.gauss(0, std)

            if metric == "sla_compliance_pct":
                latency    = metrics.get("latency_p99_ms", base.get("latency_p99_ms", 1000))
                sla_thresh = cfg.get("sla_latency_ms", 5000)
                ratio = latency / sla_thresh
                if ratio < 0.5:
                    val = 99.5 + random.gauss(0, 0.2)
                elif ratio < 0.8:
                    val = 98.5 - (ratio - 0.5) * 5 + random.gauss(0, 0.3)
                elif ratio < 1.0:
                    val = 95.0 - (ratio - 0.8) * 40 + random.gauss(0, 0.5)
                else:
                    val = max(50.0, 90.0 - (ratio - 1.0) * 30) + random.gauss(0, 1.0)

            lo, hi = METRIC_BOUNDS.get(metric, (-1e9, 1e9))
            metrics[metric] = round(max(lo, min(hi, val)), 2)

        return metrics

    def generate_training_data(self, n_samples: int = 200) -> dict:
        """Generate synthetic normal-state training samples for the IsolationForest."""
        samples: dict[str, list] = {svc: [] for svc in SERVICE_CONFIGS}
        for _ in range(n_samples):
            for svc, cfg in SERVICE_CONFIGS.items():
                m = self._compute_metrics(svc, cfg, intensity=1.0)
                samples[svc].append(m)
        return samples
