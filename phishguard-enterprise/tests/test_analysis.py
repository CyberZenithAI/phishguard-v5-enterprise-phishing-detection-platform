from app.analysis.domain_analyzer import extract_domain, heuristic_score

def test_extract_domain():
    assert extract_domain("https://www.ejemplo.com/path") == "www.ejemplo.com"

def test_heuristic_score_clean():
    score = heuristic_score("google.com")
    assert score < 30

def test_heuristic_score_suspicious():
    score = heuristic_score("secure-login-verify-account.tk")
    assert score >= 50
