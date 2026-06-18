# app/scanner/email_security/scoring.py
"""
Email Security skor motoru.

v1 -> v1.1 changes based on Sprint 1 review decisions:
- The `grade` (A-F) field was removed. The product may later show multiple scores
  such as Email Security Score and CyberMeter Score, and A-F
  letters would be confusing next to them. `total_score` +
  `status` yeterli.
- DMARC weight changed from 40 to 50, while MTA-STS and TLS-RPT changed from 10 to 5
  because missing DMARC is a greater risk for an SME than missing TLS-RPT
  daha kritik).
- All sub-score functions now derive their maximum values from
  `cls.WEIGHTS` instead of hardcoded numbers. This means if weights
  change again in the future, each function does not need
  manual updates to internal magic numbers.

Fix carried over from the previous version: `_score_dmarc` uses
`policy` + `pct` directly instead of the coarse `status` enum; `reject` and
`quarantine` bands do not overlap, so `quarantine@100%` never
receives the same score as `reject`.
"""
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class EmailSecurityScore:
    total_score: int  # 0-100
    spf: int
    dkim: int
    dmarc: int
    mta_sts: int
    tls_rpt: int
    status: str  # "EXCELLENT", "GOOD", "FAIR", "POOR", "CRITICAL"


class EmailScoringEngine:
    WEIGHTS = {
        "spf": 20,
        "dkim": 20,
        "dmarc": 50,   # Most critical control - missing DMARC is the biggest SME risk
        "mta_sts": 5,
        "tls_rpt": 5,
    }

    # Per DMARC policy (min_ratio, max_ratio) based on WEIGHTS["dmarc"].
    # pct=0 -> min_oran * weight, pct=100 -> max_oran * weight.
    # Bands do not overlap: reject lower bound is higher than quarantine upper bound.
    _DMARC_POLICY_FRACTIONS = {
        "reject": (0.75, 1.0),       # weight=50 -> 38 .. 50
        "quarantine": (0.375, 0.625),  # weight=50 -> 19 .. 31
    }
    _DMARC_NONE_FRACTION = 0.25     # izleme modu, sabit (weight=50 -> 13)
    # uncertain state, small uncertainty allowance (weight=50 -> 6)
    _DMARC_ERROR_FRACTION = 0.125

    @classmethod
    def calculate(cls, results: Dict[str, Any]) -> EmailSecurityScore:
        """Calculate weighted score"""

        spf_score = cls._score_spf(results.get("spf", {}))
        dkim_score = cls._score_dkim(results.get("dkim", {}))
        dmarc_score = cls._score_dmarc(results.get("dmarc", {}))
        mta_sts_score = cls._score_mta_sts(results.get("mta_sts", {}))
        tls_rpt_score = cls._score_tls_rpt(results.get("tls_rpt", {}))

        total = spf_score + dkim_score + dmarc_score + mta_sts_score + tls_rpt_score

        if total >= 90:
            status = "EXCELLENT"
        elif total >= 70:
            status = "GOOD"
        elif total >= 50:
            status = "FAIR"
        elif total >= 30:
            status = "POOR"
        else:
            status = "CRITICAL"

        return EmailSecurityScore(
            total_score=total,
            spf=spf_score,
            dkim=dkim_score,
            dmarc=dmarc_score,
            mta_sts=mta_sts_score,
            tls_rpt=tls_rpt_score,
            status=status,
        )

    @classmethod
    def _score_spf(cls, spf_result: Dict) -> int:
        weight = cls.WEIGHTS["spf"]

        if spf_result.get("status") == "MISSING":
            return 0
        elif spf_result.get("status") == "FAIL":
            return round(weight * 0.25)

        analysis = spf_result.get("analysis", {})
        all_mechanism = analysis.get("all_mechanism", "?all")

        if all_mechanism == "-all":
            return weight
        elif all_mechanism == "~all":
            return round(weight * 0.75)
        elif all_mechanism == "+all":
            return round(weight * 0.25)
        else:
            return round(weight * 0.5)

    @classmethod
    def _score_dkim(cls, dkim_result: Dict) -> int:
        weight = cls.WEIGHTS["dkim"]

        if dkim_result.get("status") == "VERIFIED":
            return weight
        elif dkim_result.get("status") == "NOT_VERIFIED":
            return round(weight * 0.5)  # Do not give full points; further review is needed
        else:
            return 0

    @classmethod
    def _score_dmarc(cls, dmarc_result: Dict) -> int:
        weight = cls.WEIGHTS["dmarc"]
        status = dmarc_result.get("status", "MISSING")

        if status == "MISSING":
            return 0
        if status == "ERROR":
            return round(weight * cls._DMARC_ERROR_FRACTION)

        policy = dmarc_result.get("policy") or "none"
        pct = dmarc_result.get("pct", 0)
        try:
            pct = max(0, min(100, int(pct)))
        except (TypeError, ValueError):
            pct = 0

        if policy in cls._DMARC_POLICY_FRACTIONS:
            low_frac, high_frac = cls._DMARC_POLICY_FRACTIONS[policy]
            low = weight * low_frac
            high = weight * high_frac
            return round(low + (high - low) * (pct / 100))
        elif policy == "none":
            return round(weight * cls._DMARC_NONE_FRACTION)
        else:
            return round(weight * cls._DMARC_ERROR_FRACTION)

    @classmethod
    def _score_mta_sts(cls, mta_sts_result: Dict) -> int:
        weight = cls.WEIGHTS["mta_sts"]

        if mta_sts_result.get("status") == "PASS":
            return weight
        elif mta_sts_result.get("status") == "MISSING":
            return 0
        else:
            return round(weight * 0.3)

    @classmethod
    def _score_tls_rpt(cls, tls_rpt_result: Dict) -> int:
        weight = cls.WEIGHTS["tls_rpt"]

        if tls_rpt_result.get("status") == "PASS":
            return weight
        elif tls_rpt_result.get("status") == "MISSING":
            return 0
        else:
            return round(weight * 0.3)
