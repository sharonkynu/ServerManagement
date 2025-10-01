from flask import Flask, jsonify, request, render_template, Response
import os, yaml, subprocess, socket, re, psutil, platform, requests, time

DOCKER_DIR = "/home/tst/Music/System-Metrics/Docker"
app = Flask(__name__)

# Force Docker CLI/SDK to use system Docker socket
os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"
# ----------------------------
# System Helpers
# ----------------------------
prev_net = psutil.net_io_counters()
prev_time = time.time()

def get_private_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "N/A"

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "N/A"

def is_port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("0.0.0.0", port)) != 0

def allocate_port(port_range):
    try:
        start, end = map(int, port_range.split("-"))
        if start < 1 or end > 65535 or start > end: return None
    except:
        return None
    for p in range(start, end + 1):
        if is_port_free(p):
            return p
    return None

def validate_port_range(port_range):
    return re.match(r"^\d{1,6}-\d{1,6}$", port_range)

# ----------------------------
# Routes: UI
# ----------------------------
@app.route("/")
def index():
    return render_template("dashboard_full.html")

# ----------------------------
# Routes: System Metrics
# ----------------------------
@app.route("/api/metrics")
def metrics():
    global prev_net, prev_time
    cpu_percent = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    current_time = time.time()
    net = psutil.net_io_counters()
    delta_time = current_time - prev_time
    upload_speed = (net.bytes_sent - prev_net.bytes_sent) * 8 / delta_time / 1e6
    download_speed = (net.bytes_recv - prev_net.bytes_recv) * 8 / delta_time / 1e6
    prev_net = net
    prev_time = current_time
    hostname = platform.node()
    os_type = platform.system()
    private_ip = get_private_ip()
    public_ip = get_public_ip()
    return jsonify({
        "cpu_percent": cpu_percent,
        "mem_used": round(mem.used/1e9,2),
        "mem_total": round(mem.total/1e9,2),
        "disk_used": round(disk.used/1e9,2),
        "disk_total": round(disk.total/1e9,2),
        "upload_speed": round(upload_speed,2),
        "download_speed": round(download_speed,2),
        "hostname": hostname,
        "os_type": os_type,
        "private_ip": private_ip,
        "public_ip": public_ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    })

# ----------------------------
# Routes: Docker Services
# ----------------------------
@app.route("/api/services")
def list_services():
    services = [d for d in os.listdir(DOCKER_DIR) if os.path.isdir(os.path.join(DOCKER_DIR, d))]
    return jsonify(services)

@app.route("/api/service/<service>")
def get_service(service):
    compose_file = os.path.join(DOCKER_DIR, service, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return jsonify({"error": "Not found"}), 404
    with open(compose_file,"r") as f:
        data = yaml.safe_load(f)
    for sname, s in data.get("services", {}).items():
        env = s.get("environment", {})
        if isinstance(env, dict):
            s["environment_list"] = [{"name": k, "value": v} for k,v in env.items()]
        elif isinstance(env, list):
            pairs=[]
            for e in env:
                k,_,v=e.partition("=")
                pairs.append({"name":k,"value":v})
            s["environment_list"]=pairs
        else:
            s["environment_list"]=[]
        # port range placeholder for UI (left side only)
        s["port_range"] = ""  
    return jsonify(data)

@app.route("/api/service/<service>/restart", methods=["POST"])
def restart_service(service):
    compose_file = os.path.join(DOCKER_DIR, service, "docker-compose.yml")
    if not os.path.exists(compose_file):
        return jsonify({"error":"Not found"}),404

    data = request.json
    planned_ports = {}

    # Load docker-compose.yml
    with open(compose_file,"r") as f:
        compose_data = yaml.safe_load(f)
    version = compose_data.get("version","3")  # preserve version

    # Update services
    for sname, s in data.get("services", {}).items():
        env_list = s.get("environment_list", [])
        new_env = [f"{e['name']}={e['value']}" for e in env_list if e.get("name")]
        compose_data["services"][sname]["environment"] = new_env

        # Update port range
        port_range = s.get("port_range")
        if port_range:
            if not validate_port_range(port_range):
                return jsonify({"error":f"Invalid port range for {sname}. Use start-end"}),400
            allocated_port = allocate_port(port_range)
            if allocated_port is None:
                return jsonify({"error":f"No free port in {port_range} for {sname}"}),400
            planned_ports[sname] = allocated_port

            # Preserve container port (right side)
            original_port = compose_data["services"][sname]["ports"][0]
            if isinstance(original_port, str) and ":" in original_port:
                _, container_port = original_port.split(":")
            else:
                container_port = str(allocated_port)
            compose_data["services"][sname]["ports"] = [f"{allocated_port}:{container_port}"]

    # Save updated YAML
    compose_data_to_save = {"version": version, "services": compose_data["services"]}
    with open(compose_file,"w") as f:
        yaml.safe_dump(compose_data_to_save, f, sort_keys=False)

    # Restart docker service
    def generate():
        yield "Stopping service...<br/>"
        process=subprocess.Popen(["docker-compose","-f",compose_file,"down"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        for line in iter(process.stdout.readline,''): yield line.replace("\n","<br/>")
        process.stdout.close(); process.wait()

        yield "<br/>Starting service...<br/>"
        process=subprocess.Popen(["docker-compose","-f",compose_file,"up","-d"], stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        for line in iter(process.stdout.readline,''): yield line.replace("\n","<br/>")
        process.stdout.close(); process.wait()

        for sname, port in planned_ports.items():
            yield f"{sname} assigned port: {port}<br/>"

        yield "<br/>Service restarted successfully!"

    return Response(generate(), mimetype='text/html')

# ----------------------------
# Routes: Nginx Control
# ----------------------------
@app.route("/api/nginx/<action>", methods=["POST"])
def api_nginx(action):
    if action not in ("start","stop","restart","status"):
        return jsonify({"error":"Invalid action"}),400
    try:
        cmd = ["systemctl", action, "nginx"]
        result = subprocess.run(cmd,capture_output=True,text=True)
        if action=="status":
            running = "active (running)" in result.stdout
            return jsonify({"running":running})
        return jsonify({"message":f"Nginx {action} executed"})
    except Exception as e:
        return jsonify({"error":str(e)}),500

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)

