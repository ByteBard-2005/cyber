from backend.utils.url_analyzer import analyze_url
from backend.utils.content_analyzer import analyze_content
from backend.utils.threat_checker import check_threat_feeds
from backend.utils.email_analyzer import analyze_email
from backend.utils.file_checker import check_file
from backend.utils.ai_engine import ai_score


def run_url_scan(url):
    url_result = analyze_url(url)
    content_result = analyze_content(url)
    threat_result = check_threat_feeds(url)

    ai_result = ai_score(
        url_score=url_result["score"],
        content_score=content_result["score"],
        threat_score=threat_result["score"]
    )

    all_flags = (
        url_result.get("flags", []) +
        content_result.get("flags", []) +
        threat_result.get("flags", [])
    )

    return {
        "target": url,
        "scan_type": "url",
        "verdict": ai_result["verdict"],
        "risk_score": ai_result["risk_score"],
        "flags": list(dict.fromkeys(all_flags)),
        "layers": {
            "url_analysis": url_result,
            "content_analysis": content_result,
            "threat_feeds": threat_result
        }
    }


def run_email_scan(subject, sender, body):
    email_result = analyze_email(subject, sender, body)
    ai_result = ai_score(0.0, 0.0, 0.0, email_score=email_result["score"])

    return {
        "target": f"{sender} | {subject}",
        "scan_type": "email",
        "verdict": ai_result["verdict"],
        "risk_score": ai_result["risk_score"],
        "flags": email_result["flags"]
    }


def run_file_scan(filename):
    file_result = check_file(filename)
    ai_result = ai_score(0.0, 0.0, 0.0, file_score=file_result["score"])

    return {
        "target": filename,
        "scan_type": "file",
        "verdict": ai_result["verdict"],
        "risk_score": ai_result["risk_score"],
        "flags": file_result["flags"]
    }