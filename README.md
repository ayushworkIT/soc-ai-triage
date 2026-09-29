# AI-Powered SOC Alert Triage and Incident Correlation Platform

A portfolio project demonstrating a realistic SOC (Security Operations Center)
workflow: deterministic, rule-based detection and alert correlation, with an
LLM layer used strictly as an assistant for narrative analysis, MITRE ATT&CK
mapping, and severity review - not as the detection mechanism itself.

## Architecture

```
Raw Logs (CICIDS2017 dataset)
      |
Log Ingestion (chunked CSV -> SQLite)
      |
Parsing / Normalization (clean types, handle inf/NaN, simulate source IPs)
      |
Detection Rules (volumetric, time-windowed brute-force detection)
      |
Alert Generation (structured Alert records, severity from real data quartiles)
      |
Alert Enrichment (service names, duration, attempt rate, readable descriptions)
      |
Alert Correlation (time-overlap grouping via union-find)
      |
Incident Creation (aggregated Incident records)
      |
LLM-Assisted Analysis (Claude Haiku, strict JSON schema)
      |
MITRE ATT&CK Validation (checked against official MITRE reference data)
      |
Dashboard (Streamlit) + Evaluation Report (JSON)
```


## Why an LLM, and why this architecture

The LLM is used only as an interpretation layer on top of already-detected,
already-correlated, already-verified data. Detection, alerting, and
correlation are 100% deterministic and rule-based - they never touch the
LLM, and their correctness is independently verifiable (see Evaluation
below). The LLM's job is limited to: writing a human-readable narrative,
suggesting MITRE ATT&CK techniques, giving a second opinion on severity,
and estimating false-positive likelihood - all of which are then
cross-checked against ground truth or reference data where possible.

## Dataset

[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) -
`Tuesday-WorkingHours.pcap_ISCX.csv`, containing labeled FTP-Patator and
SSH-Patator brute-force attacks alongside benign traffic.

The specific file variant used (`MachineLearningCVE`) does not include
real source/destination IP addresses (stripped for the dataset's original
ML use case). To support alert correlation, source IPs were **simulated**:
a small pool of "attacker" IPs per attack type (mimicking few-sources/
many-attempts brute-force behavior) and a larger pool of "normal" IPs for
benign traffic. This is a documented simulation, not real captured data -
see Limitations.

### Setup

```bash
# 1. Download the dataset from Kaggle (requires free account):
#    https://www.kaggle.com/datasets/cicdataset/cicids2017
#    Extract Tuesday-WorkingHours.pcap_ISCX.csv into data/raw/

# 2. Set up environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Add your Anthropic API key to a .env file:
#    ANTHROPIC_API_KEY=sk-ant-api03-...

# 4. Download the MITRE ATT&CK Enterprise dataset
curl -L -o mitre/enterprise-attack.json \
  "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# 5. Run the pipeline in order
python ingestion/load_raw_data.py
python parsing/normalize_flows.py
python detection/brute_force_rule.py
python detection/generate_alerts.py
python detection/enrich_alerts.py
python correlation/correlate_alerts.py
python correlation/build_incidents.py
python llm/run_full_analysis.py
python evaluation/run_evaluation.py

# 6. View the dashboard
streamlit run dashboard/app.py
```

## Detection Methodology

A volumetric, time-windowed rule: flag any (source_ip, destination_port)
pair with more than 10 connection attempts within a rolling 5-minute
window. Threshold chosen from the real data distribution (benign traffic
topped out at 17 connections/day; attackers started at 1,977+).

Deliberately does not use the dataset's Label column during detection -
only for post-hoc evaluation, matching how a real detection system would
have no prior knowledge of ground truth.

## Correlation Methodology

Alerts are grouped into incidents by time-window overlap, using a
union-find algorithm. At this dataset's scale (7 alerts), correlation
validates the mechanism's correctness (verified against a hand-predicted
outcome before running the code) rather than demonstrating volume
reduction at production scale.

## LLM Methodology

Claude Haiku (`claude-haiku-4-5-20251001`) is prompted with a strict
system prompt enforcing a fixed JSON output schema (narrative, confidence,
MITRE techniques, recommended actions, false-positive likelihood, severity
agreement, reasoning notes). Responses are validated: markdown code fences
are stripped defensively, and every claimed MITRE technique is checked
against the official MITRE ATT&CK Enterprise dataset for both ID validity
and name accuracy (accepting both bare technique names and the standard
"Parent: Sub-technique" display convention).

## Results

Full machine-readable report: `reports/evaluation_report.json`

| Metric | Result |
|---|---|
| Detection precision | 99.99% |
| Detection recall | 99.21% |
| Alert reduction (flows -> alerts) | 13,727 -> 7 (99.95%) |
| Correlation reduction (alerts -> incidents) | 7 -> 3 (57.14%) |
| LLM/rule-based severity agreement | 2/3 (66.67%) |
| MITRE technique hallucination rate | 2/3 (66.67%) |

### Notable findings

- **The LLM correctly identified the pipeline's only false positive** as
  high false-positive-likelihood, independently, with no ground-truth hint.
- **The LLM disagreed with rule-based severity on the SSH campaign**,
  suggesting "High" instead of "Medium" and explicitly citing the
  attack's extended 5-hour duration - independently catching a real blind
  spot in the volumetric severity rule, which ranks by raw connection
  count and underweights slow, sustained ("low and slow") attacks.
- **MITRE validation caught a subtle hallucination**: the LLM cited a
  real, valid-looking technique ID (T1021.001) but paired it with an
  incorrect name/sub-technique - a more dangerous error pattern than an
  invented ID, since it looks credible without a ground-truth cross-check.

## Limitations

- Source IPs are simulated (see Dataset section) - not real captured
  network data.
- A synthetic sequential timestamp was generated for the dataset (the
  original file has no native per-row timestamp), spacing rows evenly
  across a simulated 8-hour day.
- 17 rows with a physically impossible negative Flow Duration (a known
  CICIDS2017 capture artifact) were filtered out during normalization.
- Correlation was validated at a small, hand-verifiable scale (7 alerts);
  a production deployment would see it operating on much higher volumes
  and would benefit from a more efficient (non-pairwise) implementation.
- Evaluation covers 3 incidents from one day of one dataset - results
  characterize this specific pipeline on this specific data, not general
  LLM-assisted SOC performance.

## Future Improvements

- Additional detection rules beyond volumetric brute-force (e.g.,
  port scanning, DoS patterns) using CICIDS2017's other labeled days.
- Real IP-inclusive dataset variant for genuine (not simulated)
  correlation entities.
- A more efficient correlation algorithm (sweep-line/interval tree)
  for production-scale alert volumes.
- Confidence calibration analysis: does the LLM's stated confidence
  actually correlate with correctness across a larger incident sample.

## Tech Stack

Python, pandas, SQLAlchemy/SQLite, Anthropic Claude API, Streamlit,
MITRE ATT&CK Enterprise dataset.
