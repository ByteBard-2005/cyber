def ai_score(url_score, content_score, threat_score, email_score=None, file_score=None):
    final_score = (
        url_score * 0.40 +
        content_score * 0.30 +
        threat_score * 0.30
    )

    if email_score is not None:
        final_score = max(final_score, email_score)

    if file_score is not None:
        final_score = max(final_score, file_score)

    final_score = round(min(final_score, 1.0), 2)

    if final_score >= 0.70:
        verdict = "phishing"
    elif final_score >= 0.40:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "risk_score": final_score,
        "verdict": verdict
    }