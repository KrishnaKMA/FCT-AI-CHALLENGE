# FCT Context

## Who FCT is

First Canadian Title — Canada's largest title insurer. They process title insurance policies for **450 lenders** and **43,000 lawyers**. Since October 2025, they're a regulated entity under FINTRAC (PCMLTFA) meaning every real estate transaction must be fraud-screened.

They acquired Fintracker in January 2025 for KYC/AML capabilities.

## Why the business calendar matters

Closings cluster on **Fridays**, the **last 3 business days of each month**, and **March–June** (spring season). The worst case — last Friday of a spring month — drives 3.5x normal volume. A generic AIOps tool would alert on this every week. Sentinel adjusts thresholds to match expected load, so only real anomalies fire.

## The 7 services

| Service | What it does | Key metric |
|---|---|---|
| `fraud-screening-service` | FINTRAC fraud screening (Fintracker) | Coverage % |
| `policy-issuance-service` | Core title insurance product | P99 latency |
| `title-search-service` | Provincial land registry queries | P99 latency |
| `identity-verification-service` | KYC biometric checks | Queue depth |
| `mortgage-processing-service` | Mortgage payouts for 450 lenders | Request rate |
| `document-vault-service` | Document storage for 43k lawyers | Disk usage % |
| `property-intelligence-api` | External market intelligence API | Request rate |

## The 7 fault scenarios

| Scenario | Type | Response |
|---|---|---|
| End-of-month surge | LOAD_SURGE | Scale pods |
| Fraud screening degradation | COMPLIANCE_INCIDENT | Policy hold + escalate |
| Title search timeout | EXTERNAL_DEPENDENCY | Cached fallback + scale |
| Identity verification bottleneck | INFRASTRUCTURE_FAILURE | Scale pods |
| Document vault disk saturation | STORAGE_SATURATION | Page ops team |
| Suspicious transaction velocity | FRAUD_SIGNAL | Flag + page fraud team |
| Cascading policy failure | CASCADE | Graph RCA → fix root |

## FCT core values in every decision

Each autonomous action is tagged with the FCT value being applied:

- **"Act like an owner"** — policy hold without waiting for human confirmation when coverage drops
- **"Take intelligent risks"** — pre-scale pods 30 min before a predicted surge
- **"Solve problems"** — activate cached title data when land registry API times out
