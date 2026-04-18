"""
Messenger Bot License Server
=============================
Deploy this on Render.com (free tier)
- Manages license keys
- Validates keys + hardware IDs
- Admin API for generating/revoking keys

INSTALL (local test):
    pip install flask
    python server.py

DEPLOY TO RENDER:
    1. Push to GitHub
    2. New Web Service on render.com
    3. Build: pip install flask gunicorn
    4. Start: gunicorn server:app
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json, os, random, string, hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)  # Allow requests from admin.html

# ── CONFIG ──────────────────────────────────────────────────
# Change this to a strong secret password for admin access
ADMIN_PASSWORD = "Ararld@2341"
DATA_FILE = "licenses.json"

# ── DATA STORAGE ────────────────────────────────────────────
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"keys": {}}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def gen_key():
    """Generate a key like MBOT-X7K2-9PQR-4TJN"""
    chars = string.ascii_uppercase + string.digits
    parts = ["MBOT"] + ["".join(random.choices(chars, k=4)) for _ in range(3)]
    return "-".join(parts)

def check_admin(req):
    """Check admin password from header or query param."""
    pw = req.headers.get("X-Admin-Password") or req.args.get("password") or req.json.get("password","") if req.is_json else req.args.get("password","")
    return pw == ADMIN_PASSWORD

# ── PUBLIC ENDPOINTS (called by bot) ────────────────────────

@app.route("/validate", methods=["POST"])
def validate():
    """Bot calls this on every startup to validate license."""
    try:
        body = request.json or {}
        key = body.get("key", "").strip().upper()
        hw_id = body.get("hw_id", "").strip()
        app_version = body.get("version", "unknown")

        if not key or not hw_id:
            return jsonify({"valid": False, "reason": "Missing key or hardware ID"}), 400

        data = load_data()
        keys = data.get("keys", {})

        # Key not found
        if key not in keys:
            return jsonify({"valid": False, "reason": "Invalid license key"}), 200

        entry = keys[key]

        # Check revoked
        if entry.get("revoked"):
            return jsonify({"valid": False, "reason": "License key has been revoked"}), 200

        # Check expiry
        expiry = entry.get("expiry")
        if expiry and expiry != "lifetime":
            exp_date = datetime.fromisoformat(expiry)
            if datetime.now() > exp_date:
                return jsonify({"valid": False, "reason": f"License expired on {expiry[:10]}"}), 200

        # Check hardware ID
        registered_hw = entry.get("hw_id")
        max_pcs = entry.get("max_pcs", 1)

        if not registered_hw:
            # First use — register this PC
            entry["hw_id"] = hw_id
            entry["first_used"] = datetime.now().isoformat()
            entry["last_seen"] = datetime.now().isoformat()
            entry["version"] = app_version
            save_data(data)
            return jsonify({"valid": True, "reason": "License activated on this PC"}), 200
        elif registered_hw == hw_id:
            # Same PC — update last seen
            entry["last_seen"] = datetime.now().isoformat()
            entry["version"] = app_version
            save_data(data)
            return jsonify({"valid": True, "reason": "License valid"}), 200
        else:
            # Different PC — blocked
            return jsonify({
                "valid": False,
                "reason": "License already activated on another PC. Contact support to transfer."
            }), 200

    except Exception as e:
        return jsonify({"valid": False, "reason": f"Server error: {str(e)}"}), 500


# ── ADMIN ENDPOINTS (protected by password) ─────────────────

@app.route("/admin/keys", methods=["GET"])
def list_keys():
    """List all license keys."""
    pw = request.args.get("password", "")
    if pw != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    data = load_data()
    keys = data.get("keys", {})

    result = []
    for key, entry in keys.items():
        expiry = entry.get("expiry", "lifetime")
        if expiry and expiry != "lifetime":
            exp_date = datetime.fromisoformat(expiry)
            status = "expired" if datetime.now() > exp_date else "active"
        else:
            status = "active"
        if entry.get("revoked"):
            status = "revoked"

        result.append({
            "key": key,
            "name": entry.get("name", ""),
            "expiry": expiry,
            "status": status,
            "hw_id": entry.get("hw_id", "Not activated"),
            "first_used": entry.get("first_used", "Never"),
            "last_seen": entry.get("last_seen", "Never"),
            "version": entry.get("version", "?"),
            "revoked": entry.get("revoked", False),
            "notes": entry.get("notes", ""),
        })

    result.sort(key=lambda x: x["key"])
    return jsonify(result), 200


@app.route("/admin/generate", methods=["POST"])
def generate_key():
    """Generate a new license key."""
    try:
        body = request.json or {}
        if body.get("password") != ADMIN_PASSWORD:
            return jsonify({"error": "Unauthorized"}), 401

        name = body.get("name", "").strip()
        days = body.get("days", 30)  # 0 = lifetime
        notes = body.get("notes", "")
        max_pcs = body.get("max_pcs", 1)

        key = gen_key()
        # Make sure it's unique
        data = load_data()
        while key in data["keys"]:
            key = gen_key()

        if days == 0:
            expiry = "lifetime"
        else:
            expiry = (datetime.now() + timedelta(days=days)).isoformat()

        data["keys"][key] = {
            "name": name,
            "expiry": expiry,
            "max_pcs": max_pcs,
            "notes": notes,
            "created": datetime.now().isoformat(),
            "revoked": False,
            "hw_id": None,
            "first_used": None,
            "last_seen": None,
        }
        save_data(data)
        return jsonify({"key": key, "expiry": expiry, "name": name}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/revoke", methods=["POST"])
def revoke_key():
    """Revoke a license key."""
    try:
        body = request.json or {}
        if body.get("password") != ADMIN_PASSWORD:
            return jsonify({"error": "Unauthorized"}), 401

        key = body.get("key", "").strip().upper()
        data = load_data()
        if key not in data["keys"]:
            return jsonify({"error": "Key not found"}), 404

        data["keys"][key]["revoked"] = True
        save_data(data)
        return jsonify({"success": True, "key": key}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/unrevoke", methods=["POST"])
def unrevoke_key():
    """Re-activate a revoked key."""
    try:
        body = request.json or {}
        if body.get("password") != ADMIN_PASSWORD:
            return jsonify({"error": "Unauthorized"}), 401

        key = body.get("key", "").strip().upper()
        data = load_data()
        if key not in data["keys"]:
            return jsonify({"error": "Key not found"}), 404

        data["keys"][key]["revoked"] = False
        save_data(data)
        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/reset-pc", methods=["POST"])
def reset_pc():
    """Reset hardware ID so key can be used on a new PC."""
    try:
        body = request.json or {}
        if body.get("password") != ADMIN_PASSWORD:
            return jsonify({"error": "Unauthorized"}), 401

        key = body.get("key", "").strip().upper()
        data = load_data()
        if key not in data["keys"]:
            return jsonify({"error": "Key not found"}), 404

        data["keys"][key]["hw_id"] = None
        data["keys"][key]["first_used"] = None
        save_data(data)
        return jsonify({"success": True, "message": "PC reset. Key can now be activated on a new PC."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/delete", methods=["POST"])
def delete_key():
    """Permanently delete a key."""
    try:
        body = request.json or {}
        if body.get("password") != ADMIN_PASSWORD:
            return jsonify({"error": "Unauthorized"}), 401

        key = body.get("key", "").strip().upper()
        data = load_data()
        if key not in data["keys"]:
            return jsonify({"error": "Key not found"}), 404

        del data["keys"][key]
        save_data(data)
        return jsonify({"success": True}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    data = load_data()
    return jsonify({
        "status": "running",
        "total_keys": len(data.get("keys", {})),
        "active_keys": sum(1 for k,v in data.get("keys",{}).items()
                          if not v.get("revoked") and
                          (not v.get("expiry") or v.get("expiry")=="lifetime" or
                           datetime.fromisoformat(v["expiry"]) > datetime.now()))
    }), 200


@app.route("/", methods=["GET"])
def index():
    return "<h2>Messenger Bot License Server</h2><p>Status: Running</p>", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
