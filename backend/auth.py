from flask import session, jsonify
from functools import wraps

def login_user(user):
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]

def logout_user():
    session.clear()

def is_authenticated():
    return "user_id" in session

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return func(*args, **kwargs)
    return wrapper