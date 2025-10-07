#!/usr/bin/env python3
"""
Flask app with JSON user store (users.json). Robust login handling.
Includes simple endpoints for dashboard status and toggling SIP/H323
in docker-compose.yml files (update env and restart compose).
"""

import os
import json
import bcrypt
import platform
import psutil
import socket
import subprocess
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify
)
from typing import List, Dict, Optional
import yaml
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-secret-in-production")

# --- Config: adjust paths as needed ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# Your compose files (as you specified)
COMPOSE_PATHS = {
    "sip": "/home/sharon/tst/sip/docker-compose.yml",
    "h323": "/home/sharon/tst/h323/docker-compose.yml"
}

# -------------------------
# Utility: user JSON store
# -------------------------
def _ensure_users_file():
    """Create users.json with default admin/user if missing."""
    if not os.path.exists(USERS_FILE):
        default_users = [
            {
                "username": "admin",
                "password": bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8"),
                "role": "admin"
            },
            {
                "username": "user",
                "password": bcrypt.hashpw(b"user123", bcrypt.gensalt()).decode("utf-8"),
                "role": "user"
            }
        ]
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)


def load_users() -> List[Dict]:
    """Load users.json and return a list of user dicts.
    Accepts older formats too (dict with 'users' key or dict of username->obj).
    """
    _ensure_users_file()
    with open(USERS_FILE, "r") as f:
        data = json.load(f)

    # Normalize to list of dicts
    if isinstance(data, dict):
        # if shape is {"users":[...]}
        if "users" in data and isinstance(data["users"], list):
            return data["users"]
        # if shape is {"admin": {...}, "user": {...}} convert to list
        result = []
        for k, v in data.items():
            if isinstance(v, dict):
                # ensure username key
                v.setdefault("username", k)
                result.append(v)
        if result:
            return result
        # fallback: wrap dict as single user if it looks like a user
        if {"username", "password"} <= set(data.keys()):
            return [data]
        # unknown dict shape -> empty list
        return []
    elif isinstance(data, list):
        return data
    else:
        return []


def save_users(users: List[Dict]):
    """Save list of user dicts to users.json (atomic-ish: write to tmp then move)."""
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_FILE)


def find_user(username: str) -> Optional[Dict]:
    users = load_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None


def create_user(username: str, password: str, role: str = "user") -> bool:
    users = load_users()
    if any(u.get("username") == username for u in users):
        return False
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users.append({"username": username, "password": pw_hash, "role": role})
    save_users(users)
    return True


def update_user_password(username: str, password: str) -> bool:
    users = load_users()
    for u in users:
        if u.get("username") == username:
            u["password"] = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            save_users(users)
            return True
    return False


def delete_user(username: str) -> bool:
    users = load_users()
    new = [u for u in users if u.get("username") != username]
    if len(new) == len(users):
        return False
    save_users(new)
    return True


# -------------------------
# Login / Logout routes
# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    """Login page: uses users.json. Handles both hashed and plaintext stored passwords gracefully."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Provide username and password", "danger")
            return redirect(url_for("login"))

        user = find_user(username)
        if not user:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

        stored = user.get("password") or user.get("password_hash") or ""
        pw_bytes = password.encode("utf-8")

        # Try to verify as a bcrypt hash
        try:
            # stored must be bytes for checkpw
            if isinstance(stored, str):
                stored_bytes = stored.encode("utf-8")
            else:
                stored_bytes = stored
            if bcrypt.checkpw(pw_bytes, stored_bytes):
                # login ok
                session["username"] = username
                session["role"] = user.get("role", "user")
                return redirect(url_for("dashboard"))
            else:
                # invalid
                flash("Invalid username or password", "danger")
                return redirect(url_for("login"))
        except (ValueError, TypeError):
            # stored wasn't a valid bcrypt hash (maybe plaintext). Fall back:
            if password == stored:
                # upgrade to hashed password transparently
                update_user_password(username, password)
                session["username"] = username
                session["role"] = user.get("role", "user")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password", "danger")
                return redirect(url_for("login"))

    # GET
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -------------------------
# Dashboard / status
# -------------------------
def get_primary_ipv4() -> str:
    """Return first non-loopback IPv4 (or 'N/A')."""
    try:
        addrs = psutil.net_if_addrs()
        for iface, alist in addrs.items():
            for a in alist:
                if getattr(a, "family", None) == socket.AF_INET:
                    ip = a.address
                    if not ip.startswith("127."):
                        return ip
    except Exception:
        pass
    return "N/A"


def get_mac_for_primary() -> str:
    try:
        addrs = psutil.net_if_addrs()
        for iface, alist in addrs.items():
            for a in alist:
                # psutil.AF_LINK may not exist on all platforms. Use name attribute check fallback.
                fam = getattr(a, "family", None)
                if fam and str(fam).endswith("AF_LINK"):
                    # prefer non-loopback iface
                    return a.address
                # fallback: attribute 'address' with colon and length 17 likely mac
                if isinstance(a.address, str) and ":" in a.address and len(a.address) >= 15:
                    return a.address
    except Exception:
        pass
    return "N/A"


def get_os_release() -> str:
    try:
        out = subprocess.check_output(["lsb_release", "-d"], text=True).strip()
        # "Description:\tUbuntu 22.04.2 LTS"
        parts = out.split(":", 1)
        return parts[1].strip() if len(parts) > 1 else out
    except Exception:
        return platform.platform()


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session.get("username"))


@app.route("/status")
def status():
    """Return small JSON with live metrics (for AJAX polling)."""
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    return jsonify({
        "cpu": cpu,
        "memory": mem,
        "ip": get_primary_ipv4(),
        "mac": get_mac_for_primary(),
        "os": get_os_release(),
        "hostname": socket.gethostname()
    })


# -------------------------
# Docker Compose env updater
# -------------------------
def update_compose_env_and_restart(compose_path: str, env_changes: dict) -> (bool, str):
    """
    Load YAML compose, update environment values (H323_ENABLED / SIP_ENABLED),
    write back and run `docker compose -f <path> up -d`.
    Returns (ok, message).
    """
    if not os.path.exists(compose_path):
        return False, f"compose file not found: {compose_path}"
    try:
        with open(compose_path, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return False, f"failed to read compose: {e}"

    services = data.get("services", {})
    changed = False
    for svc_name, svc in services.items():
        env = svc.get("environment")
        # normalize environment into dict
        env_dict = {}
        if isinstance(env, list):
            for item in env:
                if isinstance(item, str) and "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
        elif isinstance(env, dict):
            env_dict = env.copy()
        else:
            env_dict = {}

        for k, v in env_changes.items():
            # set only if change
            if env_dict.get(k) != v:
                env_dict[k] = v
                changed = True

        # put back as dict (safe_dump will handle)
        svc["environment"] = env_dict
        services[svc_name] = svc

    if changed:
        data["services"] = services
        # backup
        bak = compose_path + f".bak.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        try:
            with open(bak, "w") as bf, open(compose_path, "r") as of:
                bf.write(of.read())
        except Exception:
            pass
        try:
            with open(compose_path, "w") as f:
                yaml.safe_dump(data, f, sort_keys=False)
        except Exception as e:
            return False, f"failed to write compose: {e}"

        # try to restart using docker compose or docker-compose
        cmds = [
            ["docker", "compose", "-f", compose_path, "up", "-d"],
            ["docker-compose", "-f", compose_path, "up", "-d"]
        ]
        for cmd in cmds:
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if out.returncode == 0:
                    return True, f"compose restarted with: {' '.join(cmd)}"
                # else try next
            except Exception:
                continue
        return False, "failed to run docker compose (check docker/paths/permissions)"
    else:
        return True, "no changes needed"


@app.route("/toggle_compose", methods=["POST"])
def toggle_compose():
    """
    Expects JSON: {"service_key":"sip"|"h323", "enable": true|false}
    """
    if "username" not in session:
        return jsonify({"ok": False, "msg": "not authenticated"}), 401
    payload = request.get_json() or {}
    svc_key = payload.get("service_key")
    enable = payload.get("enable")
    if svc_key not in COMPOSE_PATHS:
        return jsonify({"ok": False, "msg": "unknown service_key"}), 400
    compose_path = COMPOSE_PATHS[svc_key]
    env_var = "SIP_ENABLED" if svc_key == "sip" else "H323_ENABLED"
    value = "TRUE" if enable else "FALSE"
    ok, msg = update_compose_env_and_restart(compose_path, {env_var: value})
    return jsonify({"ok": ok, "msg": msg})


# -------------------------
# User management endpoints (admin only)
# -------------------------
@app.route("/users", methods=["GET", "POST"])
def users_page():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        flash("Admin privileges required", "danger")
        return redirect(url_for("dashboard"))

    message = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "user")
            if username and password:
                ok = create_user(username, password, role)
                message = "Created" if ok else "User already exists"
            else:
                message = "Provide username and password"
        elif action == "delete":
            username = request.form.get("username")
            if username:
                ok = delete_user(username)
                message = "Deleted" if ok else "Not found"

    users = load_users()
    return render_template("users.html", users=users, message=message)


# -------------------------
# SSL upload simple endpoint
# -------------------------
@app.route("/ssl", methods=["GET", "POST"])
def ssl_page():
    if "username" not in session:
        return redirect(url_for("login"))
    msg = None
    if request.method == "POST":
        cert_file = request.files.get("cert_file")
        key_file = request.files.get("key_file")
        cert_text = request.form.get("cert_text")
        key_text = request.form.get("key_text")
        os.makedirs(os.path.join(BASE_DIR, "ssl"), exist_ok=True)
        try:
            if cert_file:
                cert_path = os.path.join(BASE_DIR, "ssl", "cert.pem")
                cert_file.save(cert_path)
            elif cert_text:
                with open(os.path.join(BASE_DIR, "ssl", "cert.pem"), "w") as f:
                    f.write(cert_text)
            if key_file:
                key_path = os.path.join(BASE_DIR, "ssl", "key.pem")
                key_file.save(key_path)
            elif key_text:
                with open(os.path.join(BASE_DIR, "ssl", "key.pem"), "w") as f:
                    f.write(key_text)
            msg = "SSL saved"
        except Exception as e:
            msg = f"error saving SSL: {e}"
    return render_template("ssl.html", message=msg)


# -------------------------
# Nginx control (requires sudo rights)
# -------------------------
@app.route("/nginx", methods=["GET", "POST"])
def nginx_page():
    if "username" not in session:
        return redirect(url_for("login"))
    out = None
    if request.method == "POST":
        action = request.form.get("action")
        if action in ("restart", "start", "stop"):
            try:
                subprocess.run(["sudo", "systemctl", action, "nginx"], check=True, timeout=30)
                out = f"nginx {action} ok"
            except Exception as e:
                out = f"nginx {action} failed: {e}"
        else:
            out = "unknown action"
    return render_template("nginx.html", output=out)


# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # Ensure users.json exists
    _ensure_users_file()
    # Ensure PyYAML exists - if not, running will error earlier
    app.run(host="0.0.0.0", port=5000, debug=True)

