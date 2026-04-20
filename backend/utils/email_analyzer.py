def analyze_email(subject, sender, body):
    subject = (subject or "").lower()
    sender = (sender or "").lower()
    body = (body or "").lower()

    flags = []
    score = 0.0

    suspicious_subject_words = [
        "urgent", "verify", "suspended", "limited", "password", "winner", "invoice"
    ]

    suspicious_body_words = [
        "click here", "verify your account", "update now", "urgent action required",
        "reset password", "bank account", "gift card", "crypto", "otp"
    ]

    suspicious_sender_words = [
        "support-secure", "verify-team", "security-alert", "noreply-secure"
    ]

    for word in suspicious_subject_words:
        if word in subject:
            flags.append(f"suspicious_subject_{word}")
            score += 0.10

    for word in suspicious_body_words:
        if word in body:
            flags.append(f"suspicious_body_{word.replace(' ', '_')}")
            score += 0.08

    for word in suspicious_sender_words:
        if word in sender:
            flags.append("suspicious_sender_pattern")
            score += 0.20
            break

    if "http://" in body:
        flags.append("contains_insecure_link")
        score += 0.18

    if body.count("http://") + body.count("https://") >= 3:
        flags.append("many_links_in_email")
        score += 0.12

    if any(brand in sender for brand in ["paypa1", "g00gle", "micr0soft"]):
        flags.append("spoofed_sender_brand")
        score += 0.30

    return {"score": round(min(score, 1.0), 2), "flags": list(dict.fromkeys(flags))}