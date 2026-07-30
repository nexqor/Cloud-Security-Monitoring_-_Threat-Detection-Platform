"""Aggregates finding risk_points into a 0-100 security score, per the architecture doc's formula."""

SCORE_BANDS = [
    (90, "Excellent"),
    (70, "Good"),
    (40, "Warning"),
    (0, "Critical"),
]


def calculate_security_score(findings: list[dict]) -> dict:
    """
    findings: list of finding dicts, each with a 'risk_points' key.
    Score = max(0, 100 - total_risk). Uncapped total_risk is reported too,
    so >100 risk still shows how far over the line an account is.
    """
    total_risk = sum(f.get("risk_points", 0) for f in findings)
    score = max(0, 100 - total_risk)

    label = next(label for threshold, label in SCORE_BANDS if score >= threshold)

    return {
        "total_risk": total_risk,
        "score": score,
        "label": label,
        "finding_count": len(findings),
    }
