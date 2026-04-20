def check_file(filename):
    flags = []
    score = 0.0
    name = (filename or "").lower().strip()

    dangerous_ext = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".msi", ".ps1"]

    for ext in dangerous_ext:
        if name.endswith(ext):
            flags.append("dangerous_file_extension")
            score += 0.45
            break

    parts = name.split(".")
    if len(parts) >= 3:
        flags.append("double_extension_detected")
        score += 0.30

    suspicious_words = [
        "invoice", "payment", "bank", "password", "login",
        "update", "secure", "account", "urgent"
    ]

    for word in suspicious_words:
        if word in name:
            flags.append(f"suspicious_filename_{word}")
            score += 0.06

    return {"score": round(min(score, 1.0), 2), "flags": list(dict.fromkeys(flags))}