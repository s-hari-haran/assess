# SentnelOps — Resource Anomaly & Efficiency Triage

A small, explainable triage tool that takes raw infrastructure telemetry
(CPU, memory, network, exposure, identity) and decides — for each resource —
whether it is **anomalous, inefficient, or risky**, why, what to do about it,
and how confident we are.

It ships **three approaches** so you can compare them on the same data:

| Approach     | What it does                                    | Needs                  |
| ------------ | ----------------------------------------------- | ---------------------- |
| `rule_based` | Deterministic detectors — the source of truth   | Nothing (stdlib only)  |
| `ml`         | Unsupervised IsolationForest outlier detection  | `scikit-learn`, `numpy`|
| `llm`        | Groq free-tier (Llama 3.3 70B) reasoning        | `GROQ_API_KEY`         |
| `hybrid`     | Rules first, LLM rewrites the explanation       | `GROQ_API_KEY`         |

There is also a `--compare` mode that runs **rules + ML + LLM** side-by-side
and labels each row `all_agree` or `disagreement` — that's the bonus
"compare rule-based vs ML vs LLM" answer in one command.

---

## Repository layout

```
.
├── anomaly_detector.py             # the entire deliverable, runnable as a CLI
├── sample_resources.json           # 7 hand-picked test cases
├── sample_output_rule_based.json   # sample output for the rule-based approach
├── sample_output_compare.json      # sample output for --compare mode
├── requirements.txt                # optional deps for ML / LLM modes
├── .env.example                    # copy to .env and add your GROQ_API_KEY
├── .devcontainer/                  # GitHub Codespaces config (Python 3.11)
├── devcontainer.json               # dev container configuration (root)
├── .gitignore
└── README.md
```

The whole thing is **one Python file with zero required dependencies** for the
default rule-based mode. ML and LLM modes are additive.

---

## Quick start — GitHub Codespaces (recommended)

1. Push this folder to a new GitHub repo.
2. Open the repo on github.com, click **Code → Codespaces → Create codespace
   on main**. The dev container installs Python 3.11 and runs
   `pip install -r requirements.txt` automatically.
3. (Optional, only for `llm` / `hybrid` / `--compare` modes) add your Groq key:
   ```bash
   cp .env.example .env
   # edit .env and paste your key from https://console.groq.com/keys
   export $(grep -v '^#' .env | xargs)
   ```
4. Run it:
   ```bash
   # 1. Rule-based (works immediately, no key needed)
   python3 anomaly_detector.py

   # 2. ML — IsolationForest
   python3 anomaly_detector.py --approach ml

   # 3. LLM — Groq Llama 3.3 70B
   python3 anomaly_detector.py --approach llm

   # 4. Hybrid — rules decide, LLM explains
   python3 anomaly_detector.py --approach hybrid

   # 5. Bonus — all three approaches side-by-side
   python3 anomaly_detector.py --compare

   # Use your own input
   python3 anomaly_detector.py --input my_resources.json --output results.json
   ```

## Quick start — local

```bash
git clone <your-repo-url>
cd <your-repo>
pip install -r requirements.txt          # optional, only for ML/LLM
python3 anomaly_detector.py              # rule-based, zero setup
```

---

## Input format

A JSON array of resources. Required keys: `resource_id`, `cpu_avg`,
`cpu_p95`, `memory_avg`, `network_pct`. Optional: `internet_facing`,
`identity_attached`, `disk_pct`, `iops`, `region`, `instance_type`.

```json
[
  {
    "resource_id": "i-1",
    "cpu_avg": 2,
    "cpu_p95": 5,
    "memory_avg": 70,
    "network_pct": 10,
    "internet_facing": true,
    "identity_attached": true
  }
]
```

## Output format

```json
{
  "resource_id": "i-1",
  "is_anomalous": true,
  "anomaly_type": "over_provisioned",
  "reason": "CPU is consistently low (avg=2%, p95=5%) while the instance is otherwise active",
  "suggested_action": "Downsize to a smaller instance class (e.g., one tier down) and re-evaluate after 7 days",
  "confidence": 0.78,
  "severity": "medium",
  "approach": "rule_based",
  "signals": ["CPU is consistently low ..."],
  "security_note": "Internet-facing resource with an identity attached — a compromise could pivot into the cloud account"
}
```

`anomaly_type` is one of:
`over_provisioned`, `under_provisioned`, `memory_pressure`,
`network_saturation`, `idle`, `cpu_spiking`, `balanced`, `insufficient_data`.

---

## Approach — why this design

### 1. Rules are the source of truth

The assignment rewards **clarity of reasoning**. A rule engine wins on that
front because every verdict can be traced to a specific threshold an operator
can argue with. So the rule engine is the canonical implementation, and the
ML and LLM modes are wrappers that either *agree*, *disagree*, or *rewrite the
explanation*.

### 2. Independent detectors, then a priority pick

`detect_signals()` runs ~6 independent detectors (idle, over/under-provisioned,
memory pressure, network saturation, CPU spiking) — a resource can trigger
several at once. `_pick_primary()` then picks the most operationally important
one using a fixed priority:

```
memory_pressure  >  under_provisioned  >  network_saturation
                 >  cpu_spiking        >  idle
                 >  over_provisioned
```

> Safety/correctness issues beat efficiency wins. A box that is both
> memory-pressured *and* over-provisioned should be reported as
> memory-pressured first.

### 3. Confidence is calibrated, not vibes

Each detector ships with a base weight (e.g., sustained CPU saturation = 0.9,
bursty CPU = 0.7). When multiple independent signals agree we add a small
corroboration bonus (`+0.04` per extra signal) and cap at **0.97**. We never
emit 1.0 — there is always residual ambiguity in 4-feature telemetry.

### 4. Severity is separate from confidence

This is the call I think most setups get wrong. Confidence answers *"how sure
are we?"*; severity answers *"how bad is it?"*. A resource at
`memory_avg=95%` is **critical** even if confidence is 0.82, because the
*impact* of an OOM is larger than the *uncertainty* in the read.

### 5. Healthy is a first-class verdict

If nothing fires we explicitly return `anomaly_type: "balanced"` with a
`confidence` of 0.7 and an action of *"No action required"*. Silence is bad
UX for an operator — they don't know if the tool ran or skipped the resource.

### 6. Security signals are conservative on purpose

The `security_note` field flags the obvious blast-radius combinations:

- **Internet-facing + identity attached** → a compromise pivots into the cloud
  account.
- **Internet-facing + network saturation** → possible scraping / DoS / exfil.
- **Idle + identity attached** → unused credentials sitting around.

This is not a CSPM. It's a "should a human look at this?" hint — that's all.

---

## Bonus: rule-based vs ML vs LLM

### Rule-based

- **Wins**: deterministic, instant, free, fully explainable, every threshold
  is auditable.
- **Loses**: blind to anything we didn't anticipate. If a real production
  pattern doesn't match a rule, it's silently called *balanced*.

### ML — IsolationForest

I picked IsolationForest because:

1. It's **unsupervised** — we have no labelled "anomalous vs normal" data, so
   any supervised model would just bake the rule thresholds back in.
2. It works on tiny feature spaces (we only have 4 features per resource).
3. Its `decision_function` gives a continuous score we can convert into
   confidence cleanly.

The flow: fit on the whole batch, predict per-resource, then call the rule
engine on flagged resources to attribute *which* anomaly type and *what*
action. **ML answers the "is this weird?" question, rules answer
"weird how, and what do we do?"**

- **Wins**: catches genuinely unusual combinations that no rule expected
  (e.g., low CPU but high disk + high network — none of our individual
  thresholds trip, but the *joint* distribution looks alien).
- **Loses**: needs a population to compare against (≥3 resources), can't
  explain itself, and on small batches it sometimes flags whatever the
  most extreme point is even when nothing is wrong.

### LLM — Groq Llama 3.3 70B

- **Wins**: best at *explaining*. Given the same metrics, the LLM produces
  reasons that a human reads naturally — connecting "high memory + low CPU"
  to "this is probably a caching workload" instead of just listing
  thresholds.
- **Loses**: non-deterministic, costs latency (free Groq tier is fast but
  rate-limited), can hallucinate a confident-sounding reason that contradicts
  the numbers, and you can't audit *why* it said what it said.

### Hybrid — rules + LLM

The default I'd ship to production. The rule engine makes the *decision*
(deterministic, auditable). The LLM rewrites the **explanation** with the
rule output as context. This gives you the operator-friendly prose of an LLM
without giving up the reproducibility of rules. If the LLM call fails or
returns garbage, we fall back to the rule output — never block on the LLM.

### When to use what

| Situation                                 | Use         |
| ----------------------------------------- | ----------- |
| Need a verdict in a CI/CD gate            | `rule_based`|
| Don't know what "normal" looks like yet   | `ml`        |
| Building an operator dashboard            | `hybrid`    |
| Dataset has weird joint distributions     | `ml` then `rule_based` on flagged ones |
| Compliance / audit / explain-to-customer  | `rule_based`|

---

## Sample outputs (rule-based, run on `sample_resources.json`)

These are the verbatim outputs of `python3 anomaly_detector.py`:

```json
[
  {
    "resource_id": "i-1",
    "is_anomalous": true,
    "anomaly_type": "over_provisioned",
    "reason": "CPU is consistently low (avg=2.0%, p95=5.0%) while the instance is otherwise active",
    "suggested_action": "Downsize to a smaller instance class (e.g., one tier down) and re-evaluate after 7 days",
    "confidence": 0.78,
    "severity": "medium",
    "approach": "rule_based",
    "signals": ["CPU is consistently low (avg=2.0%, p95=5.0%) while the instance is otherwise active"],
    "security_note": "Internet-facing resource with an identity attached — a compromise could pivot into the cloud account"
  },
  {
    "resource_id": "i-2",
    "is_anomalous": true,
    "anomaly_type": "under_provisioned",
    "reason": "Sustained CPU saturation (avg=85.0%, p95=98.0%) — workload likely throttled",
    "suggested_action": "Scale up the instance class or add horizontal capacity behind a load balancer",
    "confidence": 0.9,
    "severity": "critical",
    "approach": "rule_based",
    "signals": ["Sustained CPU saturation (avg=85.0%, p95=98.0%) — workload likely throttled"]
  },
  {
    "resource_id": "i-3",
    "is_anomalous": true,
    "anomaly_type": "idle",
    "reason": "Resource appears idle (cpu_avg=1.0%, memory_avg=4.0%, network_pct=1.0%)",
    "suggested_action": "Investigate ownership and consider terminating or hibernating the instance",
    "confidence": 0.9,
    "severity": "medium",
    "approach": "rule_based",
    "signals": [
      "Resource appears idle (cpu_avg=1.0%, memory_avg=4.0%, network_pct=1.0%)"
    ]
  },
  {
    "resource_id": "i-4",
    "is_anomalous": true,
    "anomaly_type": "memory_pressure",
    "reason": "High memory utilization (memory_avg=92.0%) — risk of OOM",
    "suggested_action": "Move to a memory-optimized instance class or investigate a memory leak",
    "confidence": 0.8,
    "severity": "high",
    "approach": "rule_based",
    "signals": ["High memory utilization (memory_avg=92.0%) — risk of OOM"],
    "security_note": "Internet-facing resource with an identity attached — a compromise could pivot into the cloud account"
  },
  {
    "resource_id": "i--5",
    "is_anomalous": true,
    "anomaly_type": "network_saturation",
    "reason": "Network near saturation (network_pct=95.0%)",
    "suggested_action": "Upgrade network tier, enable enhanced networking, or distribute load across instances",
    "confidence": 0.85,
    "severity": "medium",
    "approach": "rule_based",
    "signals": ["Network near saturation (network_pct=95.0%)"],
    "security_note": "Public resource at network saturation — possible scraping, DoS target, or data exfiltration"
  },
  {
    "resource_id": "i-6",
    "is_anomalous": false,
    "anomaly_type": "balanced",
    "reason": "Utilization looks healthy across CPU (avg=50.0%, p95=65.0%), memory (55.0%), and network (40.0%)",
    "suggested_action": "No action required — utilization looks healthy",
    "confidence": 0.7,
    "severity": "low",
    "approach": "rule_based",
    "signals": []
  },
  {
    "resource_id": "i-7",
    "is_anomalous": true,
    "anomaly_type": "cpu_spiking",
    "reason": "Bursty CPU pattern (avg=8.0%, p95=92.0%) — short spikes against a calm baseline",
    "suggested_action": "Move to a burstable instance family or enable autoscaling on CPU p95",
    "confidence": 0.7,
    "severity": "medium",
    "approach": "rule_based",
    "signals": [
      "Bursty CPU pattern (avg=8.0%, p95=92.0%) — short spikes against a calm baseline"
    ],
    "security_note": "Internet-facing resource with an identity attached — a compromise could pivot into the cloud account"
  }
]
```

### `--compare` output (truncated)

If `GROQ_API_KEY` is not set, the `llm` column falls back to rule-based output.
ML output can also vary slightly with different datasets.

```json
[
  {
    "resource_id": "i-1",
    "rule_based": { "is_anomalous": true,  "anomaly_type": "over_provisioned",  "confidence": 0.78 },
    "ml":         { "is_anomalous": false, "anomaly_type": "balanced",          "confidence": 0.54 },
    "llm":        { "is_anomalous": true,  "anomaly_type": "over_provisioned",  "confidence": 0.78 },
    "agreement":  "disagreement"
  },
  {
    "resource_id": "i-6",
    "rule_based": { "is_anomalous": false, "anomaly_type": "balanced",          "confidence": 0.70 },
    "ml":         { "is_anomalous": false, "anomaly_type": "balanced",          "confidence": 0.05 },
    "llm":        { "is_anomalous": false, "anomaly_type": "balanced",          "confidence": 0.70 },
    "agreement":  "all_agree"
  }
]
```

The `agreement` field is the useful bit — anything labelled `disagreement`
is where the three approaches don't line up, and that's exactly the resource
a human should look at first.

---

## Tradeoffs

- **No time-series.** I treat metrics as a snapshot. A real prod system
  needs at least a 7d/30d window to distinguish "this is always idle" from
  "this is idle right now". The data model has room for it; the detectors
  don't yet use it.
- **Single-instance view.** A resource is judged in isolation. Real
  inefficiency is often a *fleet* problem — 200 instances at 5% CPU
  collectively waste more than one critical bug. The `--compare` mode hints
  at this by fitting ML across the batch, but there's no fleet-level
  reporting yet.
- **Thresholds are hand-picked.** Realistic numbers but not learned from
  data. With a labelled dataset I'd fit a small classifier and let the
  thresholds become weights.
- **No security context beyond two flags.** `internet_facing` and
  `identity_attached` are coarse. In production I'd want IAM permission
  scope, public IP allocation, security-group ingress, and VPC posture
  before making security claims.

---

## What I'd improve with more time

1. **Real time-series** — accept a 7d window per metric and detect *change*
   (sudden drops, gradual creep) instead of point-in-time thresholds.
2. **Cost grounding** — multiply waste signals by `instance_type` price so
   "downsize i-1" becomes "downsize i-1 to save $43/month".
3. **Self-evaluation** — add a small JSON test suite of (input → expected
   verdict) pairs and run it on every push. The current sample data is the
   start of this.
4. **Human feedback loop** — let an operator mark a verdict as
   *confirmed* / *false-positive* / *missed* and feed those back as
   per-tenant threshold adjustments.
5. **Better ML** — replace IsolationForest with a per-feature autoencoder
   reconstruction error so we can attribute *which dimension* drove the
   anomaly score, not just "this point is weird".

---

## Evaluation rubric — where to look

| Criterion              | Where it lives                                                      |
| ---------------------- | ------------------------------------------------------------------- |
| Clarity of thinking    | This README, sections "Approach" and "Bonus"                        |
| Approach selection     | `analyze_rules`, `analyze_ml`, `analyze_llm` in `anomaly_detector.py` |
| Output structure       | `AnalysisResult.to_json()` and the sample outputs above             |
| Practical reasoning    | `_suggest_action`, `_severity`, the priority list                   |
| Handling ambiguity     | `confidence` cap at 0.97, `balanced` verdict, graceful LLM fallback |
| Bonus: comparison      | `--compare` mode, "Bonus: rule-based vs ML vs LLM" section above    |
| Bonus: security        | `_security_note()`                                                  |
| Bonus: explanation     | `hybrid` mode — rules decide, LLM explains                          |
