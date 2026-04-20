from backend.models import get_scan_counts, get_recent_scans

def get_dashboard_data():
    counts = get_scan_counts()
    recent_rows = get_recent_scans(10)

    recent = []
    for row in recent_rows:
        recent.append({
            "id": row["id"],
            "username": row["username"],
            "scan_type": row["scan_type"],
            "target": row["target"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "flags": row["flags"] or "",
            "created_at": row["created_at"]
        })

    return {
        "cards": counts,
        "recent": recent
    }