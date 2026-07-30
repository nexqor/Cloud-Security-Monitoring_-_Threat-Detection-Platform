from app.utils.risk_scoring import calculate_security_score


def test_no_findings_is_perfect_score():
    result = calculate_security_score([])
    assert result["score"] == 100
    assert result["label"] == "Excellent"


def test_matches_architecture_doc_example():
    # Root Login (+40) + Public Bucket (+20) + Open SSH (+30) + Unused Key (+15) = 105 risk
    findings = [{"risk_points": 40}, {"risk_points": 20}, {"risk_points": 30}, {"risk_points": 15}]
    result = calculate_security_score(findings)
    assert result["total_risk"] == 105
    assert result["score"] == 0  # clamped, not negative
    assert result["label"] == "Critical"


def test_score_bands():
    assert calculate_security_score([{"risk_points": 5}])["label"] == "Excellent"   # score 95
    assert calculate_security_score([{"risk_points": 25}])["label"] == "Good"        # score 75
    assert calculate_security_score([{"risk_points": 55}])["label"] == "Warning"     # score 45
    assert calculate_security_score([{"risk_points": 85}])["label"] == "Critical"    # score 15
