#FCT AIOps Agent

An autonomous incident response agent for FCT's real estate transaction platform. It monitors 7 services, detects anomalies, finds root causes, and takes action — with awareness of FCT's business calendar and FINTRAC compliance obligations.

## Run

```bash
pip install -r requirements.txt
python main.py
```

Open **http://localhost:8000**

## What it does

- Detects anomalies using IsolationForest + Z-score, with thresholds that adjust for closing day load spikes
- Traces root causes through FCT's service dependency graph (NetworkX)
- Monitors FINTRAC fraud screening coverage every cycle — triggers a policy hold if it drops below 95%
- Pre-scales pods 30 minutes before predicted closing surges
- Acts autonomously when confidence ≥ 80%, recommends when 60–80%, escalates below that

## Dashboard controls

| Button | Action |
|---|---|
| Select scenario + Inject | Trigger any of the 7 fault scenarios |
| Friday Surge | Simulate a closing day load spike |
| Compliance Incident | Drop fraud screening below FINTRAC threshold |
| Auto toggle | Switch between autonomous and recommendation-only mode |

## Project structure

```
sentinel-aiops/
├── main.py                    # Entry point
├── simulator/
│   ├── closing_calendar.py    # Business calendar (peak/off-peak)
│   ├── fct_environment.py     # 7-service simulator
│   └── fault_scenarios.py     # 7 fault scenarios
├── agent/
│   ├── anomaly_detector.py    # IsolationForest + Z-score
│   ├── rca_engine.py          # Graph-based root cause analysis
│   ├── compliance_monitor.py  # FINTRAC coverage monitoring
│   ├── remediation.py         # Decision engine
│   └── feedback_loop.py       # Outcome tracking
├── dashboard/
│   ├── api.py
│   └── static/
│       ├── index.html
│       ├── css/dashboard.css
│       └── js/dashboard.js
└── data/sentinel.db           # SQLite (auto-created)
```

---
*FCT technical assessment — 2026 | Python · scikit-learn · networkx · FastAPI · Chart.js*
