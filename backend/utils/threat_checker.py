def check_threat_feeds(url):
    flags = []
    score = 0.0

    suspicious_patterns = [
        "paypa1", "g00gle", "faceb00k", "amaz0n", "micr0soft",
        "secure-login", "verify-account", "wallet-check"
    ]

    lowered = url.lower()

    for pattern in suspicious_patterns:
        if pattern in lowered:
            flags.append("matched_threat_pattern")
            score += 0.30
            break

    if "login" in lowered and lowered.startswith("http://"):
        flags.append("insecure_login_page")
        score += 0.20

    return {
        "score": round(min(score, 1.0), 2),
        "flags": list(dict.fromkeys(flags))
    }