# Multi-layer anomaly detection: IsolationForest + Z-score + compliance + fraud velocity.

import numpy as np
from collections import deque, defaultdict
from datetime import datetime

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    IsolationForest = None
    StandardScaler  = None


CORE_FEATURES = [
    "cpu_percent",
    "memory_percent",
    "request_rate",
    "error_rate",
    "latency_p99_ms",
    "queue_depth",
]

SERVICE_EXTRA_FEATURES = {
    "fraud-screening-service":  ["fraud_screen_coverage_pct"],
    "document-vault-service":   ["disk_usage_pct"],
    "property-intelligence-api": ["cache_hit_rate_pct"],
}

FRAUD_COVERAGE_COMPLIANCE_THRESHOLD = 95.0
FRAUD_COVERAGE_PEAK_THRESHOLD       = 97.0

Z_SCORE_THRESHOLD  = 3.0
IF_SCORE_THRESHOLD = -0.15   # raised from -0.1 — reduces startup false positives

SHORT_WINDOW = 12
LONG_WINDOW  = 60


class ServiceDetector:
    """Per-service anomaly detector: IsolationForest + Z-score."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.features     = CORE_FEATURES + SERVICE_EXTRA_FEATURES.get(service_name, [])
        self.history: deque = deque(maxlen=LONG_WINDOW)
        self.scores:  deque = deque(maxlen=LONG_WINDOW)
        self.model  = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self._trained = False
        self._rolling_means: dict = {}
        self._rolling_stds:  dict = {}

    def train(self, training_samples: list[dict]):
        """Train IsolationForest on synthetic normal data; seed z-score history."""
        X = self._extract_features(training_samples)

        if SKLEARN_AVAILABLE and X.shape[0] >= 10:
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            self.model = IsolationForest(
                contamination=0.05,
                n_estimators=100,
                random_state=42,
                n_jobs=-1,
            )
            self.model.fit(X_scaled)
            self._trained = True

        for sample in training_samples[-SHORT_WINDOW:]:
            vec = self._sample_to_vector(sample)
            if vec:
                self.history.append(vec)

        self._update_rolling_stats()

    def score(self, metrics: dict, business_context: dict) -> dict:
        """Score a single metric snapshot. Returns anomaly analysis."""
        vec = self._sample_to_vector(metrics)
        if not vec:
            return {"anomaly": False, "score": 0.0, "confidence": 0.0, "details": []}

        self.history.append(vec)
        self._update_rolling_stats()

        if_score  = 0.0
        if_anomaly = False
        if SKLEARN_AVAILABLE and self._trained and len(self.history) >= SHORT_WINDOW:
            X = np.array([vec])
            try:
                X_scaled   = self.scaler.transform(X)
                if_score   = float(self.model.score_samples(X_scaled)[0])
                if_anomaly = if_score < IF_SCORE_THRESHOLD
            except Exception:
                pass

        z_anomalies = self._zscore_analysis(vec, business_context)

        compliance_breach = False
        compliance_detail = None
        if self.service_name == "fraud-screening-service":
            coverage  = metrics.get("fraud_screen_coverage_pct", 100.0)
            threshold = (
                FRAUD_COVERAGE_PEAK_THRESHOLD
                if business_context.get("peak_window")
                else FRAUD_COVERAGE_COMPLIANCE_THRESHOLD
            )
            if coverage < threshold:
                compliance_breach = True
                compliance_detail = {
                    "metric":          "fraud_screen_coverage_pct",
                    "value":           coverage,
                    "threshold":       threshold,
                    "type":            "COMPLIANCE_BREACH",
                    "regulatory_risk": True,
                    "reasoning":       f"Coverage {coverage:.1f}% below FINTRAC minimum {threshold:.0f}%.",
                }

        # Require stronger evidence: compliance breach alone, 2+ z-score metrics, or IF + z-score corroboration
        anomaly    = compliance_breach or len(z_anomalies) >= 2 or (if_anomaly and bool(z_anomalies))
        confidence = self._compute_confidence(if_score, z_anomalies, compliance_breach)

        details = list(z_anomalies)
        if compliance_detail:
            details.append(compliance_detail)

        result = {
            "service":          self.service_name,
            "anomaly":          anomaly,
            "score":            round(if_score, 4),
            "confidence":       round(confidence, 3),
            "if_anomaly":       if_anomaly,
            "z_anomalies":      len(z_anomalies),
            "compliance_breach": compliance_breach,
            "details":          details,
            "timestamp":        datetime.utcnow().isoformat(),
        }

        self.scores.append({
            "timestamp": result["timestamp"],
            "score":     if_score,
            "anomaly":   anomaly,
        })

        return result

    def _extract_features(self, samples: list[dict]) -> np.ndarray:
        vectors = []
        for s in samples:
            v = self._sample_to_vector(s)
            if v:
                vectors.append(v)
        return np.array(vectors) if vectors else np.array([]).reshape(0, len(self.features))

    def _sample_to_vector(self, metrics: dict) -> list:
        vec = []
        for f in self.features:
            val = metrics.get(f)
            if val is None:
                return []
            vec.append(float(val))
        return vec

    def _update_rolling_stats(self):
        if len(self.history) < 3:
            return
        arr = np.array(list(self.history))
        for i, feat in enumerate(self.features):
            self._rolling_means[feat] = float(np.mean(arr[:, i]))
            self._rolling_stds[feat]  = float(np.std(arr[:, i]) + 1e-9)

    def _zscore_analysis(self, vec: list, biz_ctx: dict) -> list:
        """Z-score detection with calendar-adjusted thresholds."""
        if not self._rolling_means:
            return []

        anomalies = []
        intensity = biz_ctx.get("intensity", 1.0)
        lat_mult  = biz_ctx.get("latency_threshold_multiplier", 1.0)

        for i, feat in enumerate(self.features):
            if feat not in self._rolling_means:
                continue

            val  = vec[i]
            mean = self._rolling_means[feat]
            std  = self._rolling_stds[feat]
            z    = (val - mean) / std

            threshold = Z_SCORE_THRESHOLD
            if feat in ("latency_p99_ms",):
                threshold = Z_SCORE_THRESHOLD * lat_mult
            elif feat in ("request_rate", "queue_depth"):
                threshold = Z_SCORE_THRESHOLD * intensity
            elif feat == "fraud_screen_coverage_pct":
                threshold = 4.0  # coverage barely moves; only fire on real drops

            if abs(z) > threshold:
                direction = "high" if z > 0 else "low"
                anomalies.append({
                    "metric":    feat,
                    "value":     round(val, 2),
                    "expected":  round(mean, 2),
                    "z_score":   round(z, 2),
                    "direction": direction,
                    "threshold": round(threshold, 1),
                    "type":      "METRIC_SPIKE" if z > 0 else "METRIC_DROP",
                    "reasoning": (
                        f"{feat}={val:.1f} is {abs(z):.1f}σ {direction} of "
                        f"rolling mean ({mean:.1f}). Threshold: {threshold:.1f}σ."
                    ),
                })

        return anomalies

    def _compute_confidence(self, if_score: float, z_anomalies: list, compliance_breach: bool) -> float:
        if compliance_breach:
            return 0.97

        if_confidence = max(0.0, min(1.0, (-if_score - IF_SCORE_THRESHOLD) / 0.3))
        n_z           = len(z_anomalies)
        z_confidence  = min(1.0, n_z * 0.25)
        avg_z = (
            sum(abs(a["z_score"]) for a in z_anomalies) / len(z_anomalies)
            if z_anomalies else 0.0
        )
        z_strength = min(1.0, avg_z / 5.0)
        return min(0.99, 0.4 * if_confidence + 0.35 * z_confidence + 0.25 * z_strength)


class AnomalyDetector:
    """Coordinates per-service detectors and cross-service fraud velocity detection."""

    def __init__(self, calendar):
        self.calendar = calendar
        self._detectors = {
            svc: ServiceDetector(svc)
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
        self._anomaly_history: deque = deque(maxlen=500)
        self._velocity_history: deque = deque(maxlen=30)
        self._cycles = 0  # warmup counter

    def train(self, training_data: dict):
        """Train all service detectors. training_data: {service: [metric dicts]}"""
        for svc, detector in self._detectors.items():
            samples = training_data.get(svc, [])
            if samples:
                detector.train(samples)

    def detect(self, metrics: dict) -> list:
        """Run detection on current metrics snapshot. Returns anomaly list."""
        self._cycles += 1
        biz_ctx = self.calendar.get_context()
        results = []

        # Let rolling stats settle for 3 cycles before firing
        if self._cycles <= 3:
            for svc, detector in self._detectors.items():
                svc_metrics = metrics.get(svc, {})
                if svc_metrics:
                    detector.score(svc_metrics, biz_ctx)  # update history only
            return []

        for svc, detector in self._detectors.items():
            svc_metrics = metrics.get(svc, {})
            if not svc_metrics:
                continue
            result = detector.score(svc_metrics, biz_ctx)
            result["business_context"] = biz_ctx
            if result["anomaly"]:
                results.append(result)
                self._anomaly_history.append(result)

        velocity_anomaly = self._detect_fraud_velocity(metrics, biz_ctx)
        if velocity_anomaly:
            results.append(velocity_anomaly)

        return results

    def get_anomaly_history(self, n: int = 50) -> list:
        return list(self._anomaly_history)[-n:]

    def _detect_fraud_velocity(self, metrics: dict, biz_ctx: dict) -> dict:
        """Detect coordinated velocity spike across fraud-screening + property-intelligence."""
        fraud_svc  = metrics.get("fraud-screening-service", {})
        prop_api   = metrics.get("property-intelligence-api", {})
        fraud_rate = fraud_svc.get("request_rate", 0)
        prop_rate  = prop_api.get("request_rate", 0)

        self._velocity_history.append({
            "ts":         datetime.utcnow().isoformat(),
            "fraud_rate": fraud_rate,
            "prop_rate":  prop_rate,
        })

        if len(self._velocity_history) < 6:
            return None

        recent     = list(self._velocity_history)[-6:]
        avg_fraud  = np.mean([r["fraud_rate"] for r in recent])
        avg_prop   = np.mean([r["prop_rate"]  for r in recent])

        baseline   = list(self._velocity_history)[:6]
        base_fraud = np.mean([r["fraud_rate"] for r in baseline]) + 1
        base_prop  = np.mean([r["prop_rate"]  for r in baseline]) + 1

        fraud_spike = avg_fraud / base_fraud
        prop_spike  = avg_prop  / base_prop
        intensity   = biz_ctx.get("intensity", 1.0)

        if fraud_spike > 2.8 and prop_spike > 2.5 and intensity < 2.0:
            return {
                "service":           "CROSS_SERVICE",
                "anomaly":           True,
                "score":             -0.45,
                "confidence":        0.82,
                "if_anomaly":        True,
                "z_anomalies":       2,
                "compliance_breach": False,
                "fraud_velocity_signal": True,
                "details": [{
                    "metric":    "transaction_velocity",
                    "value":     round(avg_fraud, 1),
                    "expected":  round(base_fraud, 1),
                    "z_score":   round(fraud_spike, 2),
                    "direction": "high",
                    "type":      "FRAUD_VELOCITY_PATTERN",
                    "reasoning": (
                        f"Coordinated spike: fraud-screening {fraud_spike:.1f}x, "
                        f"property-intelligence {prop_spike:.1f}x. "
                        f"Not calendar-driven (intensity={intensity:.1f}). "
                        f"Consistent with mortgage fraud velocity pattern."
                    ),
                }],
                "timestamp":        datetime.utcnow().isoformat(),
                "business_context": biz_ctx,
            }

        return None
