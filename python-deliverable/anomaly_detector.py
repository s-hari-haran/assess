"""
SentnelOps assignment — Resource anomaly & efficiency triage.

Standalone Python reference implementation.

Usage:
    python3 anomaly_detector.py                            # rules only — no API key needed
    python3 anomaly_detector.py --input sample_resources.json
    python3 anomaly_detector.py --approach llm             # Groq free-tier (needs GROQ_API_KEY)
    python3 anomaly_detector.py --approach hybrid          # rules + Groq verification
    python3 anomaly_detector.py --approach ml              # IsolationForest (needs scikit-learn)
    python3 anomaly_detector.py --compare                  # run rules + ml + llm side-by-side

Design choices (also see README.md):

* The default approach is **rule-based**. It is deterministic, instant, and
  produces explanations that are easy to audit. A hybrid mode is provided that
  layers an LLM on top to improve the *quality* of the explanation while
  keeping the *decision* anchored in rules.
* Confidence reflects how strong/clear the evidence is — not how bad the issue
  is. "How bad" is captured by `severity`.
* When a resource looks healthy we explicitly say so (`anomaly_type =
  "balanced"`) instead of producing nothing. Silence is bad UX for an operator.
* Security signals are intentionally simple. The point is to flag obvious
  blast-radius combinations a human reviewer should look at, not to replace a
  CSPM tool.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

ANOMALY_TYPES = (
    "over_provisioned",
    "under_provisioned",
    "memory_pressure",
    "network_saturation",
    "idle",
    "cpu_spiking",
    "balanced",
    "insufficient_data",
)


@dataclass
class Resource:
    resource_id: str
    cpu_avg: float
    cpu_p95: float
    memory_avg: float
    network_pct: float
    internet_facing: bool = False
    identity_attached: bool = False
    # Optional / extensible signals
    disk_pct: float | None = None
    iops: float | None = None
    region: str | None = None
    instance_type: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Resource":
        # Tolerate extra keys; fail loudly only on the required ones.
        required = ("resource_id", "cpu_avg", "cpu_p95", "memory_avg", "network_pct")
        missing = [k for k in required if k not in d]
        if missing:
            raise ValueError(f"resource is missing required keys: {missing}")
        return cls(
            resource_id=str(d["resource_id"]),
            cpu_avg=float(d["cpu_avg"]),
            cpu_p95=float(d["cpu_p95"]),
            memory_avg=float(d["memory_avg"]),
            network_pct=float(d["network_pct"]),
            internet_facing=bool(d.get("internet_facing", False)),
            identity_attached=bool(d.get("identity_attached", False)),
            disk_pct=d.get("disk_pct"),
            iops=d.get("iops"),
            region=d.get("region"),
            instance_type=d.get("instance_type"),
        )


@dataclass
class Signal:
    type: str
    weight: float  # 0..1 — confidence in this signal alone
    message: str


@dataclass
class AnalysisResult:
    resource_id: str
    is_anomalous: bool
    anomaly_type: str
    reason: str
    suggested_action: str
    confidence: float
    severity: str
    approach: str
    signals: list[str] = field(default_factory=list)
    security_note: str | None = None

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        # Drop None fields for a cleaner output
        if d.get("security_note") is None:
            d.pop("security_note", None)
        return d


# ---------------------------------------------------------------------------
# Rule-based engine
# ---------------------------------------------------------------------------


def _clamp(n: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, n))


def detect_signals(r: Resource) -> list[Signal]:
    """Independent detectors. A resource can trigger several at once."""
    out: list[Signal] = []

    # 1. Idle / abandoned
    if r.cpu_avg < 5 and r.cpu_p95 < 10 and r.memory_avg < 15 and r.network_pct < 5:
        out.append(Signal(
            "idle",
            0.9,
            f"Resource appears idle (cpu_avg={r.cpu_avg}%, memory_avg={r.memory_avg}%, network_pct={r.network_pct}%)",
        ))

    # 2. Over-provisioned (low CPU but otherwise active)
    if r.cpu_avg < 10 and r.cpu_p95 < 20 and (r.memory_avg >= 15 or r.network_pct >= 5):
        out.append(Signal(
            "over_provisioned",
            0.78,
            f"CPU is consistently low (avg={r.cpu_avg}%, p95={r.cpu_p95}%) while the instance is otherwise active",
        ))

    # 3. Under-provisioned (sustained saturation)
    if r.cpu_avg >= 80 and r.cpu_p95 >= 90:
        out.append(Signal(
            "under_provisioned",
            0.9,
            f"Sustained CPU saturation (avg={r.cpu_avg}%, p95={r.cpu_p95}%) — workload likely throttled",
        ))

    # 4. CPU spiking (bursty)
    if r.cpu_avg < 30 and r.cpu_p95 >= 90:
        out.append(Signal(
            "cpu_spiking",
            0.7,
            f"Bursty CPU pattern (avg={r.cpu_avg}%, p95={r.cpu_p95}%) — short spikes against a calm baseline",
        ))

    # 5. Memory pressure
    if r.memory_avg >= 85:
        out.append(Signal(
            "memory_pressure",
            0.95 if r.memory_avg >= 95 else 0.8,
            f"High memory utilization (memory_avg={r.memory_avg}%) — risk of OOM",
        ))

    # 6. Network saturation
    if r.network_pct >= 90:
        out.append(Signal(
            "network_saturation",
            0.85,
            f"Network near saturation (network_pct={r.network_pct}%)",
        ))

    return out


# Priority order: correctness/safety issues before efficiency wins.
_PRIORITY = (
    "memory_pressure",
    "under_provisioned",
    "network_saturation",
    "cpu_spiking",
    "idle",
    "over_provisioned",
)


def _pick_primary(signals: list[Signal]) -> Signal | None:
    if not signals:
        return None
    for t in _PRIORITY:
        for s in signals:
            if s.type == t:
                return s
    return signals[0]


def _suggest_action(t: str) -> str:
    return {
        "idle": "Investigate ownership and consider terminating or hibernating the instance",
        "over_provisioned": "Downsize to a smaller instance class (e.g., one tier down) and re-evaluate after 7 days",
        "under_provisioned": "Scale up the instance class or add horizontal capacity behind a load balancer",
        "cpu_spiking": "Move to a burstable instance family or enable autoscaling on CPU p95",
        "memory_pressure": "Move to a memory-optimized instance class or investigate a memory leak",
        "network_saturation": "Upgrade network tier, enable enhanced networking, or distribute load across instances",
        "balanced": "No action required — utilization looks healthy",
        "insufficient_data": "Collect more telemetry before making a sizing decision",
    }[t]


def _severity(t: str, r: Resource) -> str:
    if t == "memory_pressure" and r.memory_avg >= 95:
        return "critical"
    if t == "under_provisioned" and r.cpu_p95 >= 98:
        return "critical"
    if t in ("memory_pressure", "under_provisioned"):
        return "high"
    if t == "network_saturation" and r.network_pct >= 98:
        return "high"
    if t in ("cpu_spiking", "over_provisioned", "idle", "network_saturation"):
        return "medium"
    return "low"


def _security_note(r: Resource) -> str | None:
    concerns: list[str] = []
    if r.internet_facing and r.identity_attached:
        concerns.append(
            "Internet-facing resource with an identity attached — a compromise could pivot into the cloud account"
        )
    if r.internet_facing and r.network_pct >= 90:
        concerns.append(
            "Public resource at network saturation — possible scraping, DoS target, or data exfiltration"
        )
    if r.identity_attached and r.cpu_avg < 5 and r.network_pct < 5:
        concerns.append("Idle resource still holds an identity — revoke unused credentials")
    return ". ".join(concerns) if concerns else None


def _confidence(signals: list[Signal], primary: Signal) -> float:
    """Boost when multiple independent signals agree. Cap at 0.97."""
    corroboration = max(0, len(signals) - 1) * 0.04
    return round(_clamp(primary.weight + corroboration), 2)


def analyze_rules(r: Resource) -> AnalysisResult:
    signals = detect_signals(r)
    primary = _pick_primary(signals)

    if primary is None:
        return AnalysisResult(
            resource_id=r.resource_id,
            is_anomalous=False,
            anomaly_type="balanced",
            reason=(
                f"Utilization looks healthy across CPU (avg={r.cpu_avg}%, p95={r.cpu_p95}%), "
                f"memory ({r.memory_avg}%), and network ({r.network_pct}%)"
            ),
            suggested_action=_suggest_action("balanced"),
            confidence=0.7,
            severity="low",
            approach="rule_based",
            signals=[],
            security_note=_security_note(r),
        )

    return AnalysisResult(
        resource_id=r.resource_id,
        is_anomalous=True,
        anomaly_type=primary.type,
        reason=primary.message,
        suggested_action=_suggest_action(primary.type),
        confidence=_confidence(signals, primary),
        severity=_severity(primary.type, r),
        approach="rule_based",
        signals=[s.message for s in signals],
        security_note=_security_note(r),
    )


# ---------------------------------------------------------------------------
# ML approach: unsupervised IsolationForest
# ---------------------------------------------------------------------------
#
# Why IsolationForest:
#   - Tiny, dependency-light, and works on the small 4-feature space we have.
#   - Unsupervised — we don't have labelled "anomalous vs normal" data, so any
#     supervised model would require us to label data ourselves (which would
#     just bake the rule thresholds back in).
#   - Returns an anomaly score we can convert to a confidence number.
#
# What it can't do:
#   - It can't tell us *why* something is anomalous, or *what action* to take.
#     We still call the rule engine to attach a label/action — the ML model's
#     job is purely to disagree or agree with "is this point unusual?".


def analyze_ml(resources: list[Resource]) -> list[AnalysisResult]:
    """Score the whole batch with IsolationForest, then attribute reasons via rules."""
    try:
        import numpy as np  # type: ignore
        from sklearn.ensemble import IsolationForest  # type: ignore
    except Exception:
        print(
            "[warn] scikit-learn / numpy not installed — falling back to rule-based.\n"
            "       Install with: pip install scikit-learn numpy",
            file=sys.stderr,
        )
        return [analyze_rules(r) for r in resources]

    if len(resources) < 3:
        # IsolationForest needs more than a couple of points to be meaningful.
        print("[warn] need at least 3 resources for ML mode — falling back to rules", file=sys.stderr)
        return [analyze_rules(r) for r in resources]

    feats = np.array(
        [[r.cpu_avg, r.cpu_p95, r.memory_avg, r.network_pct] for r in resources],
        dtype=float,
    )
    # contamination=auto lets the model decide; random_state for reproducibility.
    model = IsolationForest(contamination="auto", random_state=42, n_estimators=200)
    model.fit(feats)
    preds = model.predict(feats)            # -1 anomaly, +1 inlier
    scores = model.decision_function(feats) # higher = more normal

    # Normalize scores to 0..1 confidence. The further below 0 the score, the
    # more confident the model is that the point is anomalous.
    s_min, s_max = float(scores.min()), float(scores.max())
    span = (s_max - s_min) or 1.0

    results: list[AnalysisResult] = []
    for r, pred, score in zip(resources, preds, scores):
        # Rule engine attributes the *type* and *action* — ML attributes the *flag*.
        rule_view = analyze_rules(r)
        is_anomalous = bool(pred == -1)
        # Confidence: how far this point is from the inlier mass.
        normalized = 1.0 - (float(score) - s_min) / span  # 0..1, higher = more anomalous
        confidence = round(_clamp(0.5 + (normalized - 0.5) * 0.9), 2)

        if is_anomalous:
            anomaly_type = rule_view.anomaly_type if rule_view.is_anomalous else "insufficient_data"
            reason = (
                f"IsolationForest flagged this resource as a statistical outlier "
                f"(score={score:.3f}). " + (rule_view.reason if rule_view.is_anomalous else
                "Rule engine did not match a known pattern — manual review recommended.")
            )
            action = rule_view.suggested_action if rule_view.is_anomalous else (
                "Investigate manually — metrics are unusual but don't fit a known pattern"
            )
            severity = rule_view.severity if rule_view.is_anomalous else "medium"
        else:
            anomaly_type = "balanced"
            reason = (
                f"IsolationForest considers this resource normal relative to the batch "
                f"(score={score:.3f})."
            )
            action = "No action required — utilization fits the population baseline"
            severity = "low"

        results.append(AnalysisResult(
            resource_id=r.resource_id,
            is_anomalous=is_anomalous,
            anomaly_type=anomaly_type,
            reason=reason,
            suggested_action=action,
            confidence=confidence,
            severity=severity,
            approach="ml",
            signals=rule_view.signals,
            security_note=_security_note(r),
        ))

    return results


# ---------------------------------------------------------------------------
# Optional LLM / hybrid layer (Groq free tier)
# ---------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = """You are an SRE assistant that triages cloud resource telemetry.
Return ONLY a JSON object (no markdown fences, no commentary) with keys:
resource_id, is_anomalous, anomaly_type, reason, suggested_action,
confidence (0..1, cap 0.97), severity (low|medium|high|critical),
signals (list of strings), security_note (optional string).

anomaly_type must be one of:
over_provisioned, under_provisioned, memory_pressure, network_saturation,
idle, cpu_spiking, balanced, insufficient_data.

Be conservative. A single high metric is not enough to flag a resource. Healthy
resources should be marked balanced. Confidence reflects how clear the
evidence is, not how bad the issue is. Only set security_note if there is a
real concern (e.g. internet_facing AND identity_attached, idle resources still
holding credentials)."""


def analyze_llm(r: Resource, hint: AnalysisResult | None) -> AnalysisResult:
    """Call Groq's free-tier chat completions API. Falls back to rules on any failure."""
    try:
        from groq import Groq  # type: ignore
    except Exception:
        print(
            "[warn] groq SDK not installed — falling back to rules.\n"
            "       Install with: pip install groq",
            file=sys.stderr,
        )
        return analyze_rules(r) if hint is None else hint

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[warn] GROQ_API_KEY not set — falling back to rules", file=sys.stderr)
        return analyze_rules(r) if hint is None else hint

    client = Groq(api_key=api_key)
    model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

    user_blocks = [f"Resource metrics:\n{json.dumps(asdict(r), indent=2)}"]
    if hint is not None:
        user_blocks.append(
            "A rule-based engine produced this initial verdict "
            "(use as a hint, override if you disagree):\n"
            + json.dumps(hint.to_json(), indent=2)
        )

    try:
        completion = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _LLM_SYSTEM_PROMPT},
                {"role": "user", "content": "\n\n".join(user_blocks)},
            ],
            temperature=0.2,
        )
        raw = completion.choices[0].message.content or "{}"
        data = json.loads(raw)
    except Exception as e:  # network / quota / parse — fall back
        print(f"[warn] Groq call failed, falling back to rules: {e}", file=sys.stderr)
        return analyze_rules(r) if hint is None else hint

    return AnalysisResult(
        resource_id=str(data.get("resource_id", r.resource_id)),
        is_anomalous=bool(data.get("is_anomalous", False)),
        anomaly_type=str(data.get("anomaly_type", "balanced")),
        reason=str(data.get("reason", "")),
        suggested_action=str(data.get("suggested_action", "")),
        confidence=float(data.get("confidence", 0.5)),
        severity=str(data.get("severity", "low")),
        approach="hybrid" if hint is not None else "llm",
        signals=list(data.get("signals", []) or []),
        security_note=data.get("security_note"),
    )


def analyze(r: Resource, approach: str = "rule_based") -> AnalysisResult:
    if approach == "rule_based":
        return analyze_rules(r)
    if approach == "llm":
        return analyze_llm(r, hint=None)
    if approach == "hybrid":
        return analyze_llm(r, hint=analyze_rules(r))
    if approach == "ml":
        # ML needs the whole batch; single-resource call delegates to analyze_ml.
        return analyze_ml([r])[0]
    raise ValueError(f"unknown approach: {approach}")


def analyze_all(resources: Iterable[Resource], approach: str = "rule_based") -> list[AnalysisResult]:
    rs = list(resources)
    if approach == "ml":
        # ML model fits across the whole batch — don't loop one-by-one.
        return analyze_ml(rs)
    return [analyze(r, approach) for r in rs]


def compare_approaches(resources: list[Resource]) -> list[dict[str, Any]]:
    """Run rule_based, ml, and llm side-by-side. Used by --compare."""
    rule_results = analyze_all(resources, "rule_based")
    ml_results = analyze_all(resources, "ml")
    llm_results = analyze_all(resources, "llm")

    rows: list[dict[str, Any]] = []
    for r, rb, ml, lm in zip(resources, rule_results, ml_results, llm_results):
        rows.append({
            "resource_id": r.resource_id,
            "rule_based": {
                "is_anomalous": rb.is_anomalous,
                "anomaly_type": rb.anomaly_type,
                "confidence": rb.confidence,
                "reason": rb.reason,
            },
            "ml": {
                "is_anomalous": ml.is_anomalous,
                "anomaly_type": ml.anomaly_type,
                "confidence": ml.confidence,
                "reason": ml.reason,
            },
            "llm": {
                "is_anomalous": lm.is_anomalous,
                "anomaly_type": lm.anomaly_type,
                "confidence": lm.confidence,
                "reason": lm.reason,
            },
            "agreement": _agreement_label(rb, ml, lm),
        })
    return rows


def _agreement_label(rb: AnalysisResult, ml: AnalysisResult, lm: AnalysisResult) -> str:
    flags = (rb.is_anomalous, ml.is_anomalous, lm.is_anomalous)
    if all(flags) or not any(flags):
        return "all_agree"
    return "disagreement"


# ---------------------------------------------------------------------------
# Sample data + CLI
# ---------------------------------------------------------------------------

SAMPLE_RESOURCES: list[dict[str, Any]] = [
    # i-1 — over-provisioned + risky security posture (the assignment example)
    {"resource_id": "i-1", "cpu_avg": 2, "cpu_p95": 5, "memory_avg": 70, "network_pct": 10,
     "internet_facing": True, "identity_attached": True},
    # i-2 — sustained CPU saturation, internal worker
    {"resource_id": "i-2", "cpu_avg": 85, "cpu_p95": 98, "memory_avg": 40, "network_pct": 60,
     "internet_facing": False, "identity_attached": False},
    # i-3 — fully idle, no footprint anywhere
    {"resource_id": "i-3", "cpu_avg": 1, "cpu_p95": 3, "memory_avg": 4, "network_pct": 1,
     "internet_facing": False, "identity_attached": False},
    # i-4 — memory pressure, public + identity (compound risk)
    {"resource_id": "i-4", "cpu_avg": 45, "cpu_p95": 70, "memory_avg": 92, "network_pct": 30,
     "internet_facing": True, "identity_attached": True},
    # i-5 — network saturation on a public box
    {"resource_id": "i-5", "cpu_avg": 30, "cpu_p95": 55, "memory_avg": 50, "network_pct": 95,
     "internet_facing": True, "identity_attached": False},
    # i-6 — healthy / balanced
    {"resource_id": "i-6", "cpu_avg": 50, "cpu_p95": 65, "memory_avg": 55, "network_pct": 40,
     "internet_facing": False, "identity_attached": True},
    # i-7 — bursty CPU (low avg, high p95) — tests cpu_spiking vs under_provisioned
    {"resource_id": "i-7", "cpu_avg": 8, "cpu_p95": 92, "memory_avg": 35, "network_pct": 20,
     "internet_facing": True, "identity_attached": True},
]


def _load_input(path: str | None) -> list[Resource]:
    if path is None:
        return [Resource.from_dict(d) for d in SAMPLE_RESOURCES]
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise SystemExit("input file must contain a JSON array of resources")
    return [Resource.from_dict(d) for d in raw]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentnelOps anomaly & efficiency triage.")
    parser.add_argument("--input", "-i", help="Path to a JSON file with a list of resources.")
    parser.add_argument(
        "--approach",
        "-a",
        choices=("rule_based", "ml", "llm", "hybrid"),
        default="rule_based",
        help="Detection approach. 'llm'/'hybrid' need GROQ_API_KEY. 'ml' needs scikit-learn.",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Run rule_based + ml + llm side-by-side. Overrides --approach.",
    )
    parser.add_argument("--output", "-o", help="Write results to this path instead of stdout.")
    args = parser.parse_args(argv)

    resources = _load_input(args.input)

    if args.compare:
        payload = json.dumps(compare_approaches(resources), indent=2)
        result_count = len(resources)
    else:
        results = [r.to_json() for r in analyze_all(resources, approach=args.approach)]
        payload = json.dumps(results, indent=2)
        result_count = len(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"Wrote {result_count} result(s) to {args.output}")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
