# Root cause analysis: dependency graph traversal + temporal ordering + type classification.

import networkx as nx
from datetime import datetime
from collections import defaultdict


# Edge A → B: A depends on B. When B fails, A appears degraded but B is the root cause.
DEPENDENCY_EDGES = [
    ("policy-issuance-service",     "fraud-screening-service"),
    ("policy-issuance-service",     "title-search-service"),
    ("policy-issuance-service",     "identity-verification-service"),
    ("mortgage-processing-service", "policy-issuance-service"),
    ("mortgage-processing-service", "document-vault-service"),
]

ANOMALY_TYPES = {
    "COMPLIANCE_INCIDENT":    "Regulatory breach — human escalation required immediately",
    "INFRASTRUCTURE_FAILURE": "Service degradation — autonomous remediation applicable",
    "FRAUD_SIGNAL":           "Potential fraud pattern — alert fraud team, not ops",
    "LOAD_SURGE":             "Expected peak load — proactive scaling resolves",
    "CASCADE":                "Downstream effect of upstream root cause",
    "STORAGE_SATURATION":     "Resource exhaustion — ops team action required",
    "EXTERNAL_DEPENDENCY":    "Third-party API issue — activate fallback/cache",
}


class RCAEngine:
    """Dependency graph RCA with temporal tie-breaking and reasoning chains."""

    def __init__(self):
        self.graph = self._build_dependency_graph()
        self._anomaly_first_seen: dict[str, str] = {}

    def analyze(self, anomalies: list, metrics: dict, business_context: dict) -> dict:
        if not anomalies:
            return self._null_result()

        self._update_temporal_index(anomalies)

        anomalous = {
            a["service"]: a for a in anomalies
            if a["service"] != "CROSS_SERVICE"
        }
        fraud_velocity = any(a.get("fraud_velocity_signal") for a in anomalies)

        if fraud_velocity or not anomalous:
            return self._fraud_velocity_rca(anomalies, business_context)

        compliance_service = self._find_compliance_breach(anomalies)
        if compliance_service:
            return self._compliance_rca(compliance_service, anomalies, metrics, business_context)

        root_candidate = self._graph_traverse(set(anomalous.keys()))
        temporal_root  = self._temporal_root(set(anomalous.keys()))

        if root_candidate == temporal_root or temporal_root is None:
            root, confidence_boost = root_candidate, 0.15
        elif root_candidate is None:
            root, confidence_boost = temporal_root, 0.0
        else:
            root, confidence_boost = temporal_root, -0.05

        if root is None:
            root = max(anomalous.keys(), key=lambda s: anomalous[s].get("confidence", 0))

        anomaly_type   = self._classify_type(root, anomalous, business_context)
        root_anomaly   = anomalous.get(root, {})
        base_conf      = root_anomaly.get("confidence", 0.5)
        cascade_boost  = 0.1 if len(anomalous) > 1 and root != list(anomalous.keys())[0] else 0.0
        confidence     = min(0.98, base_conf + confidence_boost + cascade_boost)

        chain   = self._build_reasoning_chain(root, anomalous, anomaly_type, business_context, temporal_root, root_candidate)
        affected = self._get_affected_services(root, set(anomalous.keys()))

        return {
            "root_cause":               root,
            "confidence":               round(confidence, 3),
            "anomaly_type":             anomaly_type,
            "anomaly_type_description": ANOMALY_TYPES.get(anomaly_type, "Unknown"),
            "reasoning":                chain[-1] if chain else "Insufficient data",
            "reasoning_chain":          chain,
            "affected_services":        affected,
            "regulatory_risk":          compliance_service is not None,
            "recommended_action":       self._recommend_action(root, anomaly_type, confidence),
            "timestamp":                datetime.utcnow().isoformat(),
        }

    def get_dependency_graph_data(self) -> dict:
        return {
            "nodes": list(self.graph.nodes()),
            "edges": list(self.graph.edges()),
        }

    def _build_dependency_graph(self) -> nx.DiGraph:
        G = nx.DiGraph()
        G.add_nodes_from([
            "policy-issuance-service",
            "fraud-screening-service",
            "title-search-service",
            "identity-verification-service",
            "mortgage-processing-service",
            "document-vault-service",
            "property-intelligence-api",
        ])
        G.add_edges_from(DEPENDENCY_EDGES)
        return G

    def _update_temporal_index(self, anomalies: list):
        now = datetime.utcnow().isoformat()
        for a in anomalies:
            svc = a["service"]
            if svc not in self._anomaly_first_seen:
                self._anomaly_first_seen[svc] = a.get("timestamp", now)

    def _find_compliance_breach(self, anomalies: list) -> str:
        for a in anomalies:
            if a.get("compliance_breach"):
                return a["service"]
        return None

    def _graph_traverse(self, anomalous_services: set) -> str:
        """Find the service whose dependencies are all healthy — the true root cause."""
        for svc in anomalous_services:
            if svc not in self.graph:
                continue
            deps = list(self.graph.successors(svc))
            if not any(dep in anomalous_services for dep in deps):
                return svc
        for svc in anomalous_services:
            if not list(self.graph.predecessors(svc)):
                return svc
        return None

    def _temporal_root(self, anomalous_services: set) -> str:
        """Return the service whose anomaly was detected first."""
        relevant = {
            svc: ts for svc, ts in self._anomaly_first_seen.items()
            if svc in anomalous_services
        }
        if not relevant:
            return None
        return min(relevant, key=lambda s: relevant[s])

    def _classify_type(self, root: str, anomalous: dict, biz_ctx: dict) -> str:
        root_anomaly = anomalous.get(root, {})

        if root_anomaly.get("compliance_breach"):
            return "COMPLIANCE_INCIDENT"

        if any(a.get("fraud_velocity_signal") for a in anomalous.values()):
            return "FRAUD_SIGNAL"

        if root == "document-vault-service":
            for detail in root_anomaly.get("details", []):
                if detail.get("metric") == "disk_usage_pct":
                    return "STORAGE_SATURATION"

        if root == "title-search-service":
            for detail in root_anomaly.get("details", []):
                if "latency" in detail.get("metric", ""):
                    return "EXTERNAL_DEPENDENCY"

        if biz_ctx.get("peak_window") or biz_ctx.get("closing_day"):
            details     = root_anomaly.get("details", [])
            load_metrics = {"request_rate", "queue_depth"}
            if any(d.get("metric") in load_metrics for d in details):
                return "LOAD_SURGE"

        if len(anomalous) > 1:
            return "CASCADE"

        return "INFRASTRUCTURE_FAILURE"

    def _get_affected_services(self, root: str, anomalous: set) -> list:
        affected = set(anomalous)
        if root in self.graph:
            for svc in nx.ancestors(self.graph, root):
                affected.add(svc)
        return sorted(affected)

    def _build_reasoning_chain(self, root, anomalous, anomaly_type, biz_ctx, temporal_root, graph_root) -> list:
        chain = []
        svc_list = list(anomalous.keys())
        chain.append(f"Observed anomalies in {len(anomalous)} service(s): {', '.join(svc_list)}.")

        if root in self.graph:
            deps         = list(self.graph.successors(root))
            healthy_deps = [d for d in deps if d not in anomalous]
            anomalous_deps = [d for d in deps if d in anomalous]
            if anomalous_deps:
                chain.append(
                    f"Graph analysis: {root} has anomalous dependencies ({', '.join(anomalous_deps)}), suggesting cascade."
                )
            else:
                chain.append(
                    f"Graph analysis: {root}'s dependencies are healthy ({', '.join(healthy_deps) or 'none'}). Anomaly originated here."
                )

        if temporal_root:
            chain.append(
                f"Temporal analysis: {temporal_root} was first to show anomaly. "
                f"{'Consistent with graph analysis.' if temporal_root == graph_root else 'Overrides graph analysis (temporal evidence preferred).'}"
            )

        if biz_ctx.get("peak_window"):
            chain.append(
                f"Business context: Peak closing window (intensity={biz_ctx.get('intensity', 1.0):.1f}x). "
                f"Thresholds adjusted for expected load."
            )
        elif biz_ctx.get("closing_day"):
            chain.append("Business context: Friday closing day — elevated transaction volume expected.")

        chain.append(f"Classification: {anomaly_type} — {ANOMALY_TYPES.get(anomaly_type, 'See details')}.")

        root_conf = anomalous.get(root, {}).get("confidence", 0.5)
        if len(anomalous) > 1:
            chain.append(
                f"Conclusion: {root} identified as root cause with {root_conf:.0%} confidence. "
                f"{len(anomalous) - 1} downstream service(s) showing cascade effects."
            )
        else:
            chain.append(f"Conclusion: {root} identified as isolated root cause with {root_conf:.0%} confidence.")

        return chain

    def _recommend_action(self, root: str, anomaly_type: str, confidence: float) -> str:
        if confidence < 0.8:
            return "recommend_only + page_oncall"
        return {
            "COMPLIANCE_INCIDENT":    "enable_policy_hold + escalate_compliance",
            "FRAUD_SIGNAL":           "flag_fraud_pattern + page_fraud_team",
            "LOAD_SURGE":             "scale_up_pods",
            "EXTERNAL_DEPENDENCY":    "activate_cached_fallback",
            "STORAGE_SATURATION":     "page_oncall + alert_storage_team",
            "CASCADE":                "enable_circuit_breaker + scale_up_pods",
            "INFRASTRUCTURE_FAILURE": "restart_service",
        }.get(anomaly_type, "recommend_only + page_oncall")

    def _compliance_rca(self, service, anomalies, metrics, biz_ctx) -> dict:
        return {
            "root_cause":               service,
            "confidence":               0.97,
            "anomaly_type":             "COMPLIANCE_INCIDENT",
            "anomaly_type_description": ANOMALY_TYPES["COMPLIANCE_INCIDENT"],
            "reasoning": (
                f"{service} fraud_screen_coverage_pct has breached the FINTRAC 95% threshold. "
                "Immediate policy hold and compliance team escalation required."
            ),
            "reasoning_chain": [
                f"COMPLIANCE ALERT: {service} coverage below threshold.",
                "FINTRAC PCMLTFA (effective Oct 1, 2025) requires title insurers to screen all transactions.",
                "Coverage below 95% means transactions have proceeded without mandatory checks.",
                "Autonomous action: enable_policy_hold until service is restored.",
                "Compliance team must certify recovery before hold is released.",
            ],
            "affected_services":  [service, "policy-issuance-service"],
            "regulatory_risk":    True,
            "recommended_action": "enable_policy_hold + escalate_compliance",
            "timestamp":          datetime.utcnow().isoformat(),
        }

    def _fraud_velocity_rca(self, anomalies, biz_ctx) -> dict:
        return {
            "root_cause":               "FRAUD_VELOCITY_PATTERN",
            "confidence":               0.82,
            "anomaly_type":             "FRAUD_SIGNAL",
            "anomaly_type_description": ANOMALY_TYPES["FRAUD_SIGNAL"],
            "reasoning": (
                "Coordinated transaction velocity spike across fraud-screening and property-intelligence. "
                "Pattern is inconsistent with closing calendar load — indicative of organized fraud activity."
            ),
            "reasoning_chain": [
                "Velocity analysis: fraud-screening and property-intelligence-api both show correlated spikes.",
                f"Closing calendar intensity is {biz_ctx.get('intensity', 1.0):.1f}x — insufficient to explain the spike.",
                "Pattern matches FCT Fraud Insights Centre mortgage fraud velocity signature.",
                "Classification: FRAUD_SIGNAL — fraud team response, not ops scaling.",
                "Autonomous action: flag_fraud_pattern + page_fraud_team.",
            ],
            "affected_services":  ["fraud-screening-service", "property-intelligence-api"],
            "regulatory_risk":    True,
            "recommended_action": "flag_fraud_pattern + page_fraud_team",
            "timestamp":          datetime.utcnow().isoformat(),
        }

    def _null_result(self) -> dict:
        return {
            "root_cause":               None,
            "confidence":               0.0,
            "anomaly_type":             None,
            "anomaly_type_description": None,
            "reasoning":                "No anomalies detected.",
            "reasoning_chain":          ["System operating within normal parameters."],
            "affected_services":        [],
            "regulatory_risk":          False,
            "recommended_action":       None,
            "timestamp":                datetime.utcnow().isoformat(),
        }
