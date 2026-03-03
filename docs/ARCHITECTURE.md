# Architecture

## Components

```
ClosingCalendar  →  FCTEnvironment (7 services, 5s tick)
                          ↓
                    ComplianceMonitor   ← runs every cycle, highest priority
                    AnomalyDetector     ← IsolationForest + Z-score
                    RCAEngine           ← NetworkX dependency graph
                    RemediationEngine   ← decision table → action
                    FeedbackLoop        ← tracks outcomes, adjusts thresholds
                          ↓
                    SharedState  ←→  FastAPI  ←→  Dashboard (3s poll)
```

## Threading

| Thread | Tick |
|---|---|
| Simulator | 5s |
| Agent loop | 10s |
| Fault injector | ~90s (random) |
| FastAPI (main) | event-driven |

All writes to `SharedState` use `threading.Lock`. Dashboard reads are lock-free.

## Detection

**IsolationForest** — trained on 200 synthetic baseline samples at startup (no cold-start). One model per service, 6–8 features each.

**Z-score** — rolling window, catches sharp univariate spikes that IF may miss early in a fault.

**Calendar adjustment** — thresholds for load-sensitive metrics (latency, request rate, queue depth) are multiplied by a `1.0–3.5x` intensity factor based on day of week, day of month, and season. `fraud_screen_coverage_pct` is never adjusted.

## Root Cause Analysis

Service dependencies encoded as a directed graph:

```
mortgage-processing  →  policy-issuance  →  fraud-screening
                                          →  title-search
                                          →  identity-verification
mortgage-processing  →  document-vault
property-intelligence-api  (standalone)
```

RCA finds the anomalous service with no anomalous upstream dependencies — that's the root cause. Tie-break by first-seen timestamp.

## Autonomous action thresholds

| Confidence | Action |
|---|---|
| ≥ 80% | Autonomous execution |
| 60–80% | Recommendation only |
| < 60% | Silent / escalate |
| Compliance/fraud | Always autonomous (regulatory override) |

## Database

SQLite (`data/sentinel.db`). Two tables: `decisions` and `incidents`, each storing the full JSON payload in a `data` column for future analysis or retraining.
