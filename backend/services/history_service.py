from backend.models import get_user_scans

def get_user_history(user_id):
    rows = get_user_scans(user_id, 100)

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "scan_type": row["scan_type"],
            "target": row["target"],
            "verdict": row["verdict"],
            "risk_score": row["risk_score"],
            "flags": row["flags"] or "",
            "created_at": row["created_at"]
        })
    return result