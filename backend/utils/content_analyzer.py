import requests
from bs4 import BeautifulSoup

PHISHING_WORDS = [
    "verify your account",
    "update your password",
    "urgent action required",
    "login now",
    "confirm identity",
    "bank account",
    "credit card",
    "secure your account",
    "sign in",
]

def analyze_content(url):
    flags = []
    score = 0.0

    try:
        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        html = response.text[:300000]
        soup = BeautifulSoup(html, "html.parser")

        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", {"type": "password"})
        hidden_inputs = soup.find_all("input", {"type": "hidden"})

        if forms:
            flags.append("form_detected")
            score += 0.10

        if password_inputs:
            flags.append("password_field_detected")
            score += 0.25

        if len(hidden_inputs) >= 3:
            flags.append("many_hidden_inputs")
            score += 0.10

        for form in forms:
            action = (form.get("action") or "").lower()
            if action.startswith("http"):
                flags.append("external_form_action")
                score += 0.20
                break

        body_text = soup.get_text(" ", strip=True).lower()

        for word in PHISHING_WORDS:
            if word in body_text:
                flags.append(f"phishing_phrase_{word[:20].replace(' ', '_')}")
                score += 0.08

        score = min(score, 1.0)

    except Exception:
        flags.append("content_scan_failed")
        score += 0.05

    return {"score": round(score, 2), "flags": list(dict.fromkeys(flags))}