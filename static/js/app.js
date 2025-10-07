#!/usr/bin/env python3
import os
import json
import platform
import psutil
import socket
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import yaml
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-secret")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

COMPOSE_PATHS = {
    "sip": "/home/sharon/tst/sip/docker-compose.yml",
    "h323": "/home/sharon/tst/h323/docker-compose.yml"
}

# -------------------------
# Users
# -------------------------
def _ensure_users_file():
    if not os.path.exists(USERS_FILE):
        default_users = [
            {"username": "admin", "password": "admin123", "role": "admin"},
            {"username": "user", "password": "user123", "role": "user"}
        ]
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)

def load_users():
    _ensure_users_file()
    with open(USERS_FILE, "r") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []

def save_users(users):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_FILE)

def find_user(username):
    users = load_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None

def create_user(username, password, role="user"):
    users = load_users()
    if any(u.get("username") == username for u in users):
        return False
    users.append({"username": username, "password": password, "role": role})
    save_users(users)
    return True

def delete_user(username):
    users = load_users()
    new = [u for u in users if u.get("username") != username]
    if len(new) == len(users):
        return False
    save_users(new)
    return True

# -------------------------
# Login / Logout
# -------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = find_user(username)
        if user and user.get("password") == password:
            session["username"] = username
            session["role"] = user.get("role", "user")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -------------------------
# Dashboard
# -------------------------
def get_primary_ipv4():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET and not a.address.startswith("127."):
                    return a.address
    except: pass
    return "N/A"

def get_mac_for_primary():
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                fam = getattr(a, "family", None)
                if fam and str(fam).endswith("AF_LINK"):
                    return a.address
                if isinstance(a.address, str) and ":" in a.address:
                    return a.address
    except: pass
    return "N/A"

def get_serial_number():
    try:
        if os.path.exists("/sys/class/dmi/id/product_serial"):
            with open("/sys/class/dmi/id/product_serial") as f:
                return f.read().strip()
    except: pass
    return "N/A"

def get_os_release():
    try:
        out = subprocess.check_output(["lsb_release", "-d"], text=True).strip()
        return out.split(":", 1)[1].strip() if ":" in out else out
    except: return platform.platform()

@app.route("/dashboard")
def dashboard():
    if "username" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html", user=session.get("username"))

@app.route("/status")
def status():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory().percent
    return jsonify({
        "cpu": cpu,
        "memory": mem,
        "ip": get_primary_ipv4(),
        "mac": get_mac_for_primary(),
        "serial": get_serial_number(),
        "os": get_os_release(),
        "hostname": socket.gethostname()
    })

# -------------------------
# Docker Compose updater
# -------------------------
def update_compose_env_and_restart(compose_path, env_changes):
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
        env_dict = {}
        env = svc.get("environment", {})
        if isinstance(env, list):
            for item in env:
                if "=" in item: k,v=item.split("=",1); env_dict[k]=v
        elif isinstance(env, dict): env_dict = env.copy()
        for k,v in env_changes.items():
            if env_dict.get(k)!=v: env_dict[k]=v; changed=True
        svc["environment"]=env_dict
        services[svc_name]=svc

    if changed:
        data["services"]=services
        bak=compose_path+f".bak.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        try:
            with open(bak,"w") as bf, open(compose_path,"r") as of: bf.write(of.read())
        except: pass
        try:
            with open(compose_path,"w") as f: yaml.safe_dump(data,f,sort_keys=False)
        except Exception as e: return False,f"failed to write compose: {e}"
        for cmd in [["docker","compose","-f",compose_path,"up","-d"],["docker-compose","-f",compose_path,"up","-d"]]:
            try: out=subprocess.run(cmd,capture_output=True,text=True,timeout=120); 
            except: continue
            if out.returncode==0: return True,f"compose restarted with: {' '.join(cmd)}"
        return False,"failed to run docker compose"
    else: return True,"no changes needed"

@app.route("/toggle_compose", methods=["POST"])
def toggle_compose():
    if "username" not in session: return jsonify({"ok":False,"msg":"not authenticated"}),401
    payload=request.get_json() or {}
    svc_key=payload.get("service_key")
    enable=payload.get("enable")
    if svc_key not in COMPOSE_PATHS: return jsonify({"ok":False,"msg":"unknown service_key"}),400
    compose_path=COMPOSE_PATHS[svc_key]
    env_var="SIP_ENABLED" if svc_key=="sip" else "H323_ENABLED"
    value="TRUE" if enable else "FALSE"
    ok,msg=update_compose_env_and_restart(compose_path,{env_var:value})
    return jsonify({"ok":ok,"msg":msg})

# -------------------------
# Users page
# -------------------------
@app.route("/users", methods=["GET","POST"])
def users_page():
    if "username" not in session: return redirect(url_for("login"))
    if session.get("role")!="admin":
        flash("Admin privileges required","danger")
        return redirect(url_for("dashboard"))
    msg=None
    if request.method=="POST":
        action=request.form.get("action")
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        role=request.form.get("role","user")
        if action=="add" and username and password:
            ok=create_user(username,password,role)
            msg="Created" if ok else "User already exists"
        elif action=="delete" and username:
            ok=delete_user(username)
            msg="Deleted" if ok else "Not found"
    users=load_users()
    return render_template("users.html",users=users,message=msg)

# -------------------------
# SSL page
# -------------------------
@app.route("/ssl", methods=["GET","POST"])
def ssl_page():
    if "username" not in session: return redirect(url_for("login"))
    msg=None
    if request.method=="POST":
        cert_file=request.files.get("cert_file")
        key_file=request.files.get("key_file")
        cert_text=request.form.get("cert_text")
        key_text=request.form.get("key_text")
        os.makedirs(os.path.join(BASE_DIR,"ssl"),exist_ok=True)
        try:
            if cert_file: cert_file.save(os.path.join(BASE_DIR,"ssl","cert.pem"))
            elif cert_text: open(os.path.join(BASE_DIR,"ssl","cert.pem"),"w").write(cert_text)
            if key_file: key_file.save(os.path.join(BASE_DIR,"ssl","key.pem"))
            elif key_text: open(os.path.join(BASE_DIR,"ssl","key.pem"),"w").write(key_text)
            msg="SSL saved"
        except Exception as e: msg=f"error saving SSL: {e}"
    return render_template("ssl.html",message=msg)

# -------------------------
# Nginx control
# -------------------------
@app.route("/nginx", methods=["GET","POST"])
def nginx_page():
    if "username" not in session: return redirect(url_for("login"))
    out=None
    if request.method=="POST":
        action=request.form.get("action")
        if action in ("restart","start","stop"):
            try: subprocess.run(["sudo","systemctl",action,"nginx"],check=True,timeout=30); out=f"nginx {action} ok"
            except Exception as e: out=f"nginx {action} failed: {e}"
        else: out="unknown action"
    return render_template("nginx.html",output=out)

# -------------------------
# New Pages
# -------------------------
@app.route("/ports")
def ports_page():
    if "username" not in session: return redirect(url_for("login"))
    # Example data
    ports_info = [
        {"name": "HTTP", "port": 80, "status": "open"},
        {"name": "HTTPS", "port": 443, "status": "open"},
        {"name": "MySQL", "port": 3306, "status": "closed"},
    ]
    return render_template("ports.html", ports=ports_info)

@app.route("/remote")
def remote_page():
    if "username" not in session: return redirect(url_for("login"))
    remote_status = {"ssh": "running", "vnc": "stopped", "rdp": "running"}
    return render_template("remote.html", remotes=remote_status)

@app.route("/network")
def network_page():
    if "username" not in session: return redirect(url_for("login"))
    net_ifaces = psutil.net_if_addrs()
    return render_template("network.html", interfaces=net_ifaces)

# -------------------------
# Run
# -------------------------
if __name__=="__main__":
    _ensure_users_file()
    app.run(host="0.0.0.0",port=5000,debug=True)

