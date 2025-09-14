#!/usr/bin/env python3
import os
import json
import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import subprocess
import signal

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

AUTH_DB = '/etc/kea/auth.db'
CONFIG_FILE = '/etc/kea/kea-dhcp4.conf'
RESET_KEY_FILE = '/etc/kea/password_reset.key'

def hash_password(password):
    """Hash password with salt"""
    salt = secrets.token_hex(32)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt

def verify_password(password, hashed):
    """Verify password against hash"""
    try:
        pwd_hash, salt = hashed.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except:
        return False

def generate_reset_key():
    """Generate and save reset key"""
    reset_key = secrets.token_urlsafe(32)
    try:
        os.makedirs(os.path.dirname(RESET_KEY_FILE), exist_ok=True)
        with open(RESET_KEY_FILE, 'w') as f:
            f.write(reset_key)
        os.chmod(RESET_KEY_FILE, 0o600)  # Only readable by owner
        return True
    except:
        return False

def verify_reset_key(provided_key):
    """Verify reset key and delete file if valid"""
    try:
        with open(RESET_KEY_FILE, 'r') as f:
            stored_key = f.read().strip()
        
        if provided_key == stored_key:
            os.unlink(RESET_KEY_FILE)  # Delete key file after successful validation
            return True
        return False
    except:
        return False

def init_database():
    """Initialize SQLite database"""
    os.makedirs(os.path.dirname(AUTH_DB), exist_ok=True)
    conn = sqlite3.connect(AUTH_DB)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    os.chmod(AUTH_DB, 0o600)  # Only readable by owner

def get_user_count():
    """Get total number of users"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    except:
        return 0

def create_user(username, password):
    """Create new user"""
    try:
        init_database()
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                      (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def verify_user(username, password):
    """Verify user credentials"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return verify_password(password, result[0])
        return False
    except:
        return False

def reset_all_users():
    """Delete all users"""
    try:
        conn = sqlite3.connect(AUTH_DB)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users')
        conn.commit()
        conn.close()
        return True
    except:
        return False

def load_config():
    """Load KEA DHCP configuration"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_config(config):
    """Save KEA DHCP configuration"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def restart_kea_service():
    """Restart KEA DHCP service"""
    try:
        # Find KEA process and send SIGTERM
        result = subprocess.run(['pgrep', 'kea-dhcp4'], capture_output=True, text=True)
        if result.returncode == 0:
            pid = int(result.stdout.strip())
            os.kill(pid, signal.SIGTERM)
        return True
    except:
        return False

def validate_config(config):
    """Validate KEA configuration"""
    try:
        temp_file = '/tmp/kea-test.conf'
        with open(temp_file, 'w') as f:
            json.dump(config, f)
        result = subprocess.run(['kea-dhcp4', '-t', temp_file], capture_output=True)
        os.unlink(temp_file)
        return result.returncode == 0
    except:
        return False

@app.before_request
def require_auth():
    """Check authentication for protected routes"""
    if request.endpoint in ['login', 'setup', 'request_reset', 'reset_password', 'static']:
        return

    if get_user_count() == 0 and request.endpoint != 'setup':
        return redirect(url_for('setup'))

    if 'user' not in session and request.endpoint != 'login':
        return redirect(url_for('login'))

@app.route('/')
def index():
    """Main dashboard"""
    config = load_config()
    return render_template('dashboard.html', config=config)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup for first user"""
    if get_user_count() > 0:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username and password:
            if create_user(username, password):
                flash('Setup completed successfully!')
                return redirect(url_for('login'))
            else:
                flash('Failed to create user!')
        else:
            flash('Please provide both username and password')

    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verify_user(username, password):
            session['user'] = username
            # Clean up any unused reset key on successful login
            try:
                if os.path.exists(RESET_KEY_FILE):
                    os.unlink(RESET_KEY_FILE)
            except:
                pass
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/request-reset', methods=['GET', 'POST'])
def request_reset():
    """Generate password reset key"""
    if request.method == 'POST':
        if generate_reset_key():
            flash(f'Reset key generated successfully! Check {RESET_KEY_FILE} on the server.')
        else:
            flash('Failed to generate reset key!')
        return redirect(url_for('request_reset'))

    return render_template('request_reset.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Reset username and password with reset key"""
    if request.method == 'POST':
        reset_key = request.form['reset_key']
        new_username = request.form['username']
        new_password = request.form['password']

        if not reset_key or not new_username or not new_password:
            flash('All fields are required!')
            return render_template('reset_password.html')

        if verify_reset_key(reset_key):
            # Clear all existing users and create new admin
            if reset_all_users() and create_user(new_username, new_password):
                flash('Username and password reset successfully!')
                return redirect(url_for('login'))
            else:
                flash('Failed to reset credentials!')
        else:
            flash('Invalid reset key!')

    return render_template('reset_password.html')

@app.route('/config')
def config():
    """Configuration page"""
    config = load_config()
    return render_template('config.html', config=config)

@app.route('/settings')
def settings():
    """Settings management page"""
    config = load_config()
    return render_template('settings.html', config=config)

@app.route('/update-settings', methods=['POST'])
def update_settings():
    """Update settings via form"""
    try:
        config = load_config()
        if not config:
            config = {"Dhcp4": {}}

        # Update global settings
        config["Dhcp4"]["renew-timer"] = int(request.form.get('renew_timer', 900))
        config["Dhcp4"]["rebind-timer"] = int(request.form.get('rebind_timer', 1800))
        config["Dhcp4"]["valid-lifetime"] = int(request.form.get('valid_lifetime', 3600))

        # Update interfaces
        interfaces = request.form.get('interfaces', '*').split(',')
        config["Dhcp4"]["interfaces-config"] = {
            "interfaces": [i.strip() for i in interfaces],
            "dhcp-socket-type": "raw"
        }

        # Initialize multi-threading section
        if "multi-threading" not in config["Dhcp4"]:
            config["Dhcp4"]["multi-threading"] = {
                "enable-multi-threading": False
            }

        # Set authoritative mode
        config["Dhcp4"]["authoritative"] = True

        # Initialize control-socket section
        if "control-socket" not in config["Dhcp4"]:
            config["Dhcp4"]["control-socket"] = {
                "socket-type": "unix",
                "socket-name": "/run/kea/kea4-ctrl-socket"
            }

        # Initialize lease-database section with all required defaults
        if "lease-database" not in config["Dhcp4"]:
            config["Dhcp4"]["lease-database"] = {
                "type": "memfile",
                "persist": True,
                "name": "/var/lib/kea/kea-leases4.csv",
                "lfc-interval": 3600
            }

        # Initialize expired-leases-processing section
        if "expired-leases-processing" not in config["Dhcp4"]:
            config["Dhcp4"]["expired-leases-processing"] = {
                "reclaim-timer-wait-time": 10,
                "flush-reclaimed-timer-wait-time": 25,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
                "unwarned-reclaim-cycles": 5
            }

        # Initialize loggers section
        if "loggers" not in config["Dhcp4"]:
            config["Dhcp4"]["loggers"] = [{
                "name": "kea-dhcp4",
                "output_options": [{"output": "stdout"}],
                "severity": "INFO",
                "debuglevel": 0
            }]

        if validate_config(config):
            save_config(config)
            flash('Settings updated successfully!')
        else:
            flash('Configuration validation failed!')

    except Exception as e:
        flash(f'Error updating settings: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/add-subnet', methods=['POST'])
def add_subnet():
    """Add new subnet"""
    try:
        config = load_config()
        if not config or "Dhcp4" not in config:
            config = {"Dhcp4": {"subnet4": []}}

        if "subnet4" not in config["Dhcp4"]:
            config["Dhcp4"]["subnet4"] = []

        # Auto-assign next ID
        existing_ids = [s.get("id", 0) for s in config["Dhcp4"]["subnet4"]]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        # Normalize subnet (ensure CIDR)
        raw_subnet = request.form.get('subnet')
        if raw_subnet and '/' not in raw_subnet:
            subnet = raw_subnet.strip() + '/24'
        else:
            subnet = raw_subnet.strip() if raw_subnet else None

        subnet_data = {
            "id": next_id,
            "subnet": subnet,  # always valid CIDR now
            "pools": [{
                "pool": f"{request.form.get('pool_start')}-{request.form.get('pool_end')}"
            }],
            "option-data": []
        }

        # Add gateway if provided
        if request.form.get('gateway'):
            subnet_data["option-data"].append({
                "name": "routers",
                "data": request.form.get('gateway')
            })

        # Add DNS if provided
        if request.form.get('dns_servers'):
            subnet_data["option-data"].append({
                "name": "domain-name-servers",
                "data": request.form.get('dns_servers')
            })

        # Add domain name if provided
        if request.form.get('domain_name'):
            subnet_data["option-data"].append({
                "name": "domain-name",
                "data": request.form.get('domain_name')
            })

        config["Dhcp4"]["subnet4"].append(subnet_data)

        if validate_config(config):
            save_config(config)
            flash('Subnet added successfully!')
        else:
            flash('Invalid subnet configuration!')

    except Exception as e:
        flash(f'Error adding subnet: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/delete-subnet/<int:subnet_index>', methods=['POST'])
def delete_subnet(subnet_index):
    """Delete subnet"""
    try:
        config = load_config()
        if config and "Dhcp4" in config and "subnet4" in config["Dhcp4"]:
            if 0 <= subnet_index < len(config["Dhcp4"]["subnet4"]):
                config["Dhcp4"]["subnet4"].pop(subnet_index)
                save_config(config)
                flash('Subnet deleted successfully!')
            else:
                flash('Invalid subnet index!')

    except Exception as e:
        flash(f'Error deleting subnet: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/add-reservation', methods=['POST'])
def add_reservation():
    """Add static IP reservation"""
    try:
        config = load_config()
        subnet_index = int(request.form.get('subnet_index'))

        if (config and "Dhcp4" in config and "subnet4" in config["Dhcp4"] and
            0 <= subnet_index < len(config["Dhcp4"]["subnet4"])):

            if "reservations" not in config["Dhcp4"]["subnet4"][subnet_index]:
                config["Dhcp4"]["subnet4"][subnet_index]["reservations"] = []

            reservation = {
                "hw-address": request.form.get('mac_address'),
                "ip-address": request.form.get('ip_address')
            }

            if request.form.get('hostname'):
                reservation["hostname"] = request.form.get('hostname')

            config["Dhcp4"]["subnet4"][subnet_index]["reservations"].append(reservation)

            if validate_config(config):
                save_config(config)
                flash('Reservation added successfully!')
            else:
                flash('Invalid reservation configuration!')
        else:
            flash('Invalid subnet index!')

    except Exception as e:
        flash(f'Error adding reservation: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/delete-reservation/<int:subnet_index>/<int:reservation_index>', methods=['POST'])
def delete_reservation(subnet_index, reservation_index):
    """Delete static IP reservation"""
    try:
        config = load_config()
        if (config and "Dhcp4" in config and "subnet4" in config["Dhcp4"] and
            0 <= subnet_index < len(config["Dhcp4"]["subnet4"])):

            subnet = config["Dhcp4"]["subnet4"][subnet_index]
            if ("reservations" in subnet and
                0 <= reservation_index < len(subnet["reservations"])):

                subnet["reservations"].pop(reservation_index)
                save_config(config)
                flash('Reservation deleted successfully!')
            else:
                flash('Invalid reservation index!')
        else:
            flash('Invalid subnet index!')

    except Exception as e:
        flash(f'Error deleting reservation: {str(e)}')

    return redirect(url_for('settings'))

@app.route('/update-config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        config_data = request.get_json()

        if validate_config(config_data):
            save_config(config_data)
            flash('Configuration updated successfully!')
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Invalid configuration'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/restart-service', methods=['POST'])
def restart_service():
    """Restart KEA DHCP service"""
    try:
        if restart_kea_service():
            return jsonify({'success': True, 'message': 'Service restarted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to restart service'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def parse_lease_file():
    """Parse KEA lease file"""
    lease_files = [
        '/var/lib/kea/kea-leases4.csv'  # Updated to match config file path
    ]

    leases = []

    for lease_file in lease_files:
        try:
            with open(lease_file, 'r') as f:
                # KEA CSV format: address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state
                lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(',')
                        if len(parts) >= 10:
                            lease = {
                                'ip': parts[0],
                                'mac': parts[1],
                                'client_id': parts[2],
                                'lifetime': parts[3],
                                'expire': parts[4],
                                'subnet_id': parts[5],
                                'hostname': parts[8] if parts[8] else 'Unknown',
                                'state': parts[9]
                            }
                            # Only include active leases
                            if lease['state'] == '0':  # 0 = default (active)
                                leases.append(lease)
            break  # If we successfully read a file, stop trying others
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"Error parsing lease file {lease_file}: {e}")
            continue

    return leases

@app.route('/leases')
def leases():
    """View current leases"""
    try:
        active_leases = parse_lease_file()
        return render_template('leases.html', leases=active_leases)
    except Exception as e:
        return render_template('leases.html', leases=[], error=str(e))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)