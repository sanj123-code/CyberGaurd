import re

def rule_based_check(url):
    score = 0

    if len(url) > 75:
        score += 2

    if not url.startswith("https://"):
        score += 2

    if "@" in url:
        score += 3

    if url.count('.') > 3:
        score += 2

    keywords = ["login", "verify", "bank", "secure", "account", "update"]
    for word in keywords:
        if word in url.lower():
            score += 2

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", url):
        score += 3

    if "//" in url[8:]:
        score += 2

    if "-" in url:
        score += 1

    if score >= 6:
        return "Dangerous ❌"
    elif score >= 3:
        return "Suspicious ⚠️"
    else:
        return "Safe ✅"