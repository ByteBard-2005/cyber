from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "signin", "confirm", "password", "wallet"
]

BRAND_NAMES = [
    "paypal", "google", "facebook", "instagram", "amazon", "microsoft", "apple"
]

def analyze_url(url):
    parsed = urlparse(url)
    flags = []
    score = 0.0

    domain = parsed.netloc.lower()
    full = url.lower()

    if parsed.scheme == "http":
        flags.append("insecure_http")
        score += 0.20

    if len(url) > 75:
        flags.append("long_url")
        score += 0.10

    if "@" in url:
        flags.append("contains_at_symbol")
        score += 0.15

    if full.count("-") >= 2:
        flags.append("excessive_hyphens")
        score += 0.08

    subdomain_parts = domain.split(".")
    if len(subdomain_parts) > 3:
        flags.append("too_many_subdomains")
        score += 0.12

    for word in SUSPICIOUS_KEYWORDS:
        if word in full:
            flags.append(f"suspicious_keyword_{word}")
            score += 0.08

    for brand in BRAND_NAMES:
        if brand in full:
            fake_variant_1 = brand.replace("l", "1")
            fake_variant_2 = brand.replace("o", "0")
            if fake_variant_1 in full or fake_variant_2 in full:
                flags.append("possible_typosquatting")
                score += 0.25
                break

    score = min(score, 1.0)
    return {"score": round(score, 2), "flags": list(dict.fromkeys(flags))}