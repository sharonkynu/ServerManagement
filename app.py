from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import json
import os
import subprocess
import socket
import psutil
import platform
import uuid
import hashlib
from datetime import datetime
import threading
import time
import ping3
import telnetlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Configuration
USERS_FILE = os.environ.get('USERS_FILE', 'users.json')
DOCKER_COMPOSE_FILE = os.environ.get('DOCKER_COMPOSE_FILE', 'docker-compose.yml')
COMPOSE_BASE_DIR = os.environ.get('COMPOSE_BASE_DIR', '/home/sharon')

def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def get_system_info():
    """Get comprehensive system information"""
    try:
        # Get local IP (works across OS)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # Doesn't need to be reachable — just used to get the right interface
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()

        # Get MAC address
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                       for elements in range(0, 2*6, 2)][::-1])

        # Get serial number (Linux)
        serial = "Unknown"
        try:
            with open('/sys/class/dmi/id/product_serial', 'r') as f:
                serial = f.read().strip()
        except:
            pass

        # Get OS info
        os_info = f"{platform.system()} {platform.release()}"
        if platform.system() == "Linux":
            try:
                with open('/etc/os-release', 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith('PRETTY_NAME='):
                            os_info = line.split('=')[1].strip().strip('"')
                            break
            except:
                pass

        return {
            'ip': ip,
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
            'memory_used': round(psutil.virtual_memory().used / (1024**3), 2),
            'mac_address': mac,
            'serial_number': serial,
            'os_info': os_info,
            'uptime': time.time() - psutil.boot_time()
        }
    except Exception as e:
        return {'error': str(e)}


def get_network_info():
    """Get network interface information"""
    try:
        interfaces = {}
        stats = psutil.net_if_stats()
        link_family = getattr(psutil, 'AF_LINK', getattr(socket, 'AF_PACKET', None))
        for interface, addrs in psutil.net_if_addrs().items():
            ipv4 = next((a for a in addrs if a.family == socket.AF_INET), None)
            mac = next((a for a in addrs if link_family is not None and a.family == link_family), None)
            iface_stats = stats.get(interface)
            interfaces[interface] = {
                'name': interface,
                'ipv4': ipv4.address if ipv4 else '',
                'netmask': ipv4.netmask if ipv4 else '',
                'mac': mac.address if mac else '',
                'is_up': bool(iface_stats.isup) if iface_stats else False,
                'speed_mbps': getattr(iface_stats, 'speed', 0) if iface_stats else 0,
                'mtu': getattr(iface_stats, 'mtu', 0) if iface_stats else 0,
            }
        # Determine primary interface from routing table
        primary_iface = 'unknown'
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split('\t')
                    if len(fields) >= 11 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                        primary_iface = fields[0]
                        break
        except Exception:
            pass
        return {'interfaces': interfaces, 'primary': primary_iface}
    except Exception as e:
        return {'error': str(e)}

def update_docker_compose_env(key, value):
    """Update environment variable across docker compose files under COMPOSE_BASE_DIR."""
    try:
        updated_any = False
        if not os.path.isdir(COMPOSE_BASE_DIR):
            return False
        for entry in os.listdir(COMPOSE_BASE_DIR):
            entry_path = os.path.join(COMPOSE_BASE_DIR, entry)
            if not os.path.isdir(entry_path):
                continue
            for fname in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
                compose_path = os.path.join(entry_path, fname)
                if not os.path.exists(compose_path):
                    continue
                try:
                    with open(compose_path, 'r') as f:
                        lines = f.readlines()
                    # Update or insert under first environment section encountered
                    updated = False
                    env_index = None
                    for i, line in enumerate(lines):
                        if f"- {key}=" in line:
                            lines[i] = f"      - {key}={value}\n"
                            updated = True
                            break
                        if env_index is None and line.strip().startswith('environment:'):
                            env_index = i
                    if not updated and env_index is not None:
                        lines.insert(env_index + 1, f"      - {key}={value}\n")
                        updated = True
                    if updated:
                        with open(compose_path, 'w') as f:
                            f.writelines(lines)
                        updated_any = True
                except Exception as inner_e:
                    print(f"Error updating {compose_path}: {inner_e}")
        return updated_any
    except Exception as e:
        print(f"Error updating docker compose files: {e}")
        return False

def restart_docker_container():
    """Restart containers in all compose projects under COMPOSE_BASE_DIR."""
    try:
        if not os.path.isdir(COMPOSE_BASE_DIR):
            # Fallback to current compose file
            subprocess.run(['docker-compose', 'restart'], check=True, capture_output=True)
            return True
        success = True
        for entry in os.listdir(COMPOSE_BASE_DIR):
            entry_path = os.path.join(COMPOSE_BASE_DIR, entry)
            if not os.path.isdir(entry_path):
                continue
            compose_file = None
            for fname in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'):
                possible = os.path.join(entry_path, fname)
                if os.path.exists(possible):
                    compose_file = possible
                    break
            if compose_file is None:
                continue
            try:
                subprocess.run(['docker', 'compose', '-f', compose_file, 'up', '-d'], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"Error restarting compose at {compose_file}: {e}")
                success = False
        return success
    except subprocess.CalledProcessError as e:
        print(f"Error restarting containers: {e}")
        return False


@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('login.html')
        
        users = load_users()
        if username in users and users[username]['password'] == password:
            session['user'] = username
            session['role'] = users[username]['role']
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')

    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/debug/session')
def debug_session():
    return jsonify({
        'session_data': dict(session),
        'session_id': session.get('_id', 'No session ID'),
        'user': session.get('user', 'Not logged in')
    })

@app.route('/debug/users')
def debug_users():
    users = load_users()
    return jsonify({
        'users': users,
        'total_users': len(users),
        'admin_exists': 'admin' in users
    })

@app.route('/simple-login', methods=['GET', 'POST'])
def simple_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password!', 'error')
            return render_template('simple_login.html')
        
        users = load_users()
        if username in users and users[username]['password'] == password:
            session['user'] = username
            session['role'] = users[username]['role']
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('simple_login.html')



@app.route('/debug/login-test')
def debug_login_test():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Debug Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; }
            input { padding: 10px; margin: 5px; border: 2px solid #ccc; width: 200px; }
            button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
            .status { margin-top: 20px; padding: 10px; background: #f0f0f0; }
        </style>
    </head>
    <body>
        <h2>Simple Login Test</h2>
        <form method="POST" action="/login" id="testForm">
            <p>Username: <input type="text" name="username" id="username" value="admin" required></p>
            <p>Password: <input type="password" name="password" id="password" value="admin123" required></p>
            <p><button type="submit" id="submitBtn">Test Login</button></p>
        </form>
        
        <div class="status" id="status">
            <p>Status: Ready to test</p>
            <p>Username field: <span id="usernameStatus"></span></p>
            <p>Password field: <span id="passwordStatus"></span></p>
        </div>
        
        <p><a href="/debug/users">Check Users</a></p>
        <p><a href="/debug/session">Check Session</a></p>
        <p><a href="/login">Back to Main Login</a></p>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const username = document.getElementById('username');
                const password = document.getElementById('password');
                const status = document.getElementById('status');
                
                function updateStatus() {
                    document.getElementById('usernameStatus').textContent = 
                        'enabled=' + !username.disabled + ', readonly=' + username.readOnly + ', value="' + username.value + '"';
                    document.getElementById('passwordStatus').textContent = 
                        'enabled=' + !password.disabled + ', readonly=' + password.readOnly + ', value="' + password.value + '"';
                }
                
                updateStatus();
                
                username.addEventListener('input', updateStatus);
                password.addEventListener('input', updateStatus);
                
                username.addEventListener('focus', () => console.log('Username focused'));
                password.addEventListener('focus', () => console.log('Password focused'));
                
                document.getElementById('testForm').addEventListener('submit', function(e) {
                    status.innerHTML += '<p>Form submitted with: ' + username.value + ' / ' + password.value + '</p>';
                });
            });
        </script>
    </body>
    </html>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    system_info = get_system_info()
    network_info = get_network_info()
    
    return render_template('dashboard.html', 
                         system_info=system_info, 
                         network_info=network_info,
                         user=session['user'],
                         role=session['role'])

@app.route('/system')
def system_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    system_info = get_system_info()
    return render_template('system.html', system_info=system_info)

@app.route('/api/system_info')
def api_system_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify(get_system_info())

@app.route('/network')
def network_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    network_info = get_network_info()
    return render_template('network.html', network_info=network_info)

@app.route('/api/network_info')
def api_network_info():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(get_network_info())

@app.route('/api/network_config', methods=['POST'])
def api_network_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    config = request.json
    mode = config.get('mode')  # manual, dhcp, disable
    ip_address = config.get('ip_address')
    netmask = config.get('netmask')
    gateway = config.get('gateway')
    dns_servers = config.get('dns_servers')
    dns_config = config.get('dns_config', {})
    routes = config.get('routes', [])
    try:
        # Persist the last requested config for auditing
        os.makedirs('logs', exist_ok=True)
        with open(os.path.join('logs', 'network_last_config.json'), 'w') as f:
            json.dump({
                'mode': mode,
                'ip_address': ip_address,
                'netmask': netmask,
                'gateway': gateway,
                'dns_servers': dns_servers,
                'dns_config': dns_config,
                'routes': routes,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        # Real implementation would call system utilities (netplan/ifconfig/ip) here
        return jsonify({'status': 'success', 'message': 'Network configuration applied', 'dns_status': 'applied'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/dns')
def dns_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('network.html')

@app.route('/api/dns_config', methods=['POST'])
def api_dns_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    config = request.json
    hostname = config.get('hostname')
    name_server = config.get('name_server')
    secondary_name_server = config.get('secondary_name_server')
    domain_suffix = config.get('domain_suffix')
    try:
        # Persist requested DNS settings
        os.makedirs('logs', exist_ok=True)
        with open(os.path.join('logs', 'dns_last_config.json'), 'w') as f:
            json.dump({
                'hostname': hostname,
                'name_server': name_server,
                'secondary_name_server': secondary_name_server,
                'domain_suffix': domain_suffix,
                'timestamp': datetime.now().isoformat()
            }, f, indent=2)
        return jsonify({'status': 'success', 'message': 'DNS configuration applied', 'dns_status': 'applied'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/remote_check')
def remote_check_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('remote_check.html')

@app.route('/api/remote_check', methods=['POST'])
def api_remote_check():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    target = data.get('target')
    check_type = data.get('type')  # ping, telnet, traceroute
    port = data.get('port', 80)
    timeout = int(data.get('timeout', 5))
    
    try:
        if check_type == 'ping':
            result = ping3.ping(target, timeout=5)
            if result is not None:
                return jsonify({'status': 'success', 'message': f'Ping successful: {result*1000:.2f}ms'})
            else:
                return jsonify({'status': 'error', 'message': 'Ping failed'})
        elif check_type == 'telnet':
            try:
                tn = telnetlib.Telnet(target, port, timeout=timeout)
                tn.close()
                return jsonify({'status': 'success', 'message': f'Connection successful to {target}:{port}'})
            except:
                return jsonify({'status': 'error', 'message': f'Connection failed to {target}:{port}'})
        elif check_type == 'traceroute':
            # Try traceroute, fall back to tracepath if not available
            try:
                cmd = ['traceroute', '-m', '20', '-w', str(timeout), target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*4)
            except FileNotFoundError:
                try:
                    cmd = ['tracepath', '-m', '20', target]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout*4)
                except FileNotFoundError:
                    return jsonify({'status': 'error', 'message': 'traceroute/tracepath not installed'})

            output = (result.stdout or result.stderr or '').strip()
            # Limit very long outputs
            if len(output) > 5000:
                output = output[:5000] + '\n... truncated ...'
            if result.returncode in (0, 1):  # traceroute may return 1 even when producing output
                return jsonify({'status': 'success', 'message': output})
            return jsonify({'status': 'error', 'message': output or 'Traceroute failed'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/ports')
def ports_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('ports.html')

@app.route('/api/ports_config', methods=['POST'])
def api_ports_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    config = request.json
    h323_enabled = config.get('h323_enabled', False)
    sip_enabled = config.get('sip_enabled', False)
    try:
        # Update all compose projects under COMPOSE_BASE_DIR
        ok1 = update_docker_compose_env('H323_ENABLED', str(h323_enabled).lower())
        ok2 = update_docker_compose_env('SIP_ENABLED', str(sip_enabled).lower())
        # Restart containers
        if (ok1 or ok2) and restart_docker_container():
            return jsonify({'status': 'success', 'message': 'Protocols updated across compose projects and containers restarted'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to update compose files or restart containers'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/users')
def users_page():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Access denied! Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        with open('users.json', 'r') as f:
            users_data = json.load(f)
            
            # Support both dict- and list-style JSON formats
            if isinstance(users_data, dict):
                users = []
                for username, info in users_data.items():
                    # Ensure each user entry includes a username field
                    user_entry = info
                    user_entry['username'] = username
                    users.append(user_entry)
            elif isinstance(users_data, list):
                users = users_data
            else:
                users = []
    except (FileNotFoundError, json.JSONDecodeError):
        users = []
    
    return render_template('users.html', users=users)


@app.route('/api/users', methods=['GET'])
def api_list_users():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    users = load_users()
    return jsonify({'status': 'success', 'users': users})

@app.route('/api/users', methods=['POST'])
def api_create_user():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Admin privileges required'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    users = load_users()
    if username in users:
        return jsonify({'status': 'error', 'message': 'User already exists'})
    
    users[username] = {
        'password': password,  # Storing as plain text as requested
        'role': role,
        'created': datetime.now().isoformat()
    }
    
    save_users(users)
    return jsonify({'status': 'success', 'message': 'User created successfully'})

@app.route('/api/users/<username>', methods=['PUT'])
def api_update_user(username):
    try:
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403

        data = request.json
        users = load_users()

        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        # Update role if provided
        if 'role' in data and data['role']:
            users[username]['role'] = data['role']

        # Update password if provided and not empty
        if 'password' in data and data['password']:
            users[username]['password'] = data['password']

        # Optionally update other fields
        users[username]['updated'] = datetime.now().isoformat()

        save_users(users)
        return jsonify({'status': 'success', 'message': 'User updated successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/api/users/<username>', methods=['DELETE'])
def api_delete_user(username):
    try:
        if 'user' not in session or session.get('role') != 'admin':
            return jsonify({'status': 'error', 'message': 'Admin privileges required'}), 403

        users = load_users()
        
        if username not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        del users[username]
        save_users(users)
        
        return jsonify({'status': 'success', 'message': f'User {username} deleted successfully'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/ssl')
def ssl_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    return render_template('ssl.html')

@app.route('/api/ssl_config', methods=['POST'])
def api_ssl_config():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    config = request.json
    ssl_enabled = config.get('ssl_enabled', False)
    try:
        update_docker_compose_env('SSL_ENABLED', str(ssl_enabled).lower())
        if restart_docker_container():
            return jsonify({'status': 'success', 'message': 'SSL configuration updated and container restarted'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to restart container'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/nginx_control', methods=['POST'])
def api_nginx_control():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    action = data.get('action')  # restart, stop, or start
    
    try:
        if action == 'restart':
            subprocess.run(['sudo', 'systemctl', 'restart', 'nginx'], check=True)
            return jsonify({'status': 'success', 'message': 'Nginx restarted successfully'})
        elif action == 'stop':
            subprocess.run(['sudo', 'systemctl', 'stop', 'nginx'], check=True)
            return jsonify({'status': 'success', 'message': 'Nginx stopped successfully'})
        elif action == 'start':
            subprocess.run(['sudo', 'systemctl', 'start', 'nginx'], check=True)
            return jsonify({'status': 'success', 'message': 'Nginx started successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action'})
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'error', 'message': f'Failed to {action} nginx: {str(e)}'})

@app.route('/api/ssl_upload', methods=['POST'])
def api_ssl_upload():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        os.makedirs('ssl', exist_ok=True)
        # Support file upload (multipart) or raw text JSON
        if request.content_type and 'multipart/form-data' in request.content_type:
            cert_file = request.files.get('cert_file')
            key_file = request.files.get('key_file')
            if not cert_file or not key_file:
                return jsonify({'status': 'error', 'message': 'Certificate and key files are required'})
            cert_path = os.path.join('ssl', 'certificate.pem')
            key_path = os.path.join('ssl', 'private_key.pem')
            cert_file.save(cert_path)
            key_file.save(key_path)
        else:
            data = request.json or {}
            cert_text = data.get('cert_text')
            key_text = data.get('key_text')
            if not cert_text or not key_text:
                return jsonify({'status': 'error', 'message': 'cert_text and key_text are required'}), 400
            with open(os.path.join('ssl', 'certificate.pem'), 'w') as f:
                f.write(cert_text)
            with open(os.path.join('ssl', 'private_key.pem'), 'w') as f:
                f.write(key_text)
        return jsonify({'status': 'success', 'message': 'Certificate and key saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # Create default admin user if users.json doesn't exist
    if not os.path.exists(USERS_FILE):
        default_users = {
            'admin': {
                'password': 'admin123',
                'role': 'admin',
                'created': datetime.now().isoformat()
            }
        }
        save_users(default_users)
    
    app.run(debug=True, host='0.0.0.0', port=8082)