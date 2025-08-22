# license_system.py - Complete License Authentication System
# Upload this single file to GitHub
# Flask server with SQLite database, HWID detection, and Discord webhooks

import sqlite3
import bcrypt
import requests
import platform
import subprocess
import hashlib
import psutil
import socket
from datetime import datetime, timedelta
import uuid
from flask import Flask, request, jsonify
import os
import threading
import time

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'wigga'
    DATABASE_URL = 'database.db'
    DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL') or 'https://discord.com/api/webhooks/1370023737814028318/ogERpIPBsKk3JhNsYDBsuu8we4Zhg_HA-HqV-9PkCJE9ZM2vvp4GGkUIrJra9lJnrp_1'

# Database Models
class Database:
    def __init__(self, db_path='database.db'):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Licenses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                user_id INTEGER,
                hwid VARCHAR(255),
                expires_at TIMESTAMP,
                activated_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                license_key VARCHAR(255),
                hwid VARCHAR(255),
                ip_address VARCHAR(45),
                action VARCHAR(50),
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized successfully")

class User:
    @staticmethod
    def create_user(username, password):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    @staticmethod
    def verify_user(username, password):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return user['id']
        return None
    
    @staticmethod
    def get_user_by_id(user_id):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user

class License:
    @staticmethod
    def generate_key():
        """Generate a random license key"""
        return str(uuid.uuid4()).replace('-', '').upper()[:24]
    
    @staticmethod
    def create_license(expires_days=30):
        """Create a new license key"""
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        license_key = License.generate_key()
        expires_at = datetime.now() + timedelta(days=expires_days) if expires_days else None
        
        cursor.execute(
            'INSERT INTO licenses (license_key, expires_at) VALUES (?, ?)',
            (license_key, expires_at)
        )
        conn.commit()
        conn.close()
        return license_key
    
    @staticmethod
    def activate_license(license_key, user_id, hwid):
        """Activate a license key for a user"""
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        # Check if license exists and is not activated
        cursor.execute(
            'SELECT * FROM licenses WHERE license_key = ? AND user_id IS NULL AND is_active = 1',
            (license_key,)
        )
        license_row = cursor.fetchone()
        
        if not license_row:
            conn.close()
            return False, "License key not found or already activated"
        
        # Check if license is expired
        if license_row['expires_at']:
            expires_at = datetime.fromisoformat(license_row['expires_at'])
            if datetime.now() > expires_at:
                conn.close()
                return False, "License key has expired"
        
        # Activate license
        cursor.execute(
            'UPDATE licenses SET user_id = ?, hwid = ?, activated_at = ? WHERE license_key = ?',
            (user_id, hwid, datetime.now(), license_key)
        )
        conn.commit()
        conn.close()
        return True, "License activated successfully"
    
    @staticmethod
    def validate_license(license_key, hwid):
        """Validate a license key"""
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT l.*, u.username 
            FROM licenses l 
            JOIN users u ON l.user_id = u.id 
            WHERE l.license_key = ? AND l.is_active = 1
        ''', (license_key,))
        
        license_row = cursor.fetchone()
        conn.close()
        
        if not license_row:
            return False, "Invalid license key", None
        
        if license_row['hwid'] != hwid:
            return False, "Hardware ID mismatch - license bound to different device", None
        
        if license_row['expires_at']:
            expires_at = datetime.fromisoformat(license_row['expires_at'])
            if datetime.now() > expires_at:
                return False, "License has expired", None
        
        return True, "License is valid", license_row

class Logger:
    @staticmethod
    def log_action(user_id, license_key, hwid, ip_address, action, success):
        """Log user actions"""
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (user_id, license_key, hwid, ip_address, action, success)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, license_key, hwid, ip_address, action, success))
        
        conn.commit()
        conn.close()

# Utility Functions
def get_hwid():
    """Generate unique hardware ID"""
    try:
        system = platform.system()
        machine = platform.machine()
        processor = platform.processor()
        
        # Get MAC address
        mac_address = None
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK and addr.address and addr.address != '00:00:00:00:00:00':
                    mac_address = addr.address
                    break
            if mac_address:
                break
        
        # Get disk serial (Windows only)
        disk_serial = ""
        if system == "Windows":
            try:
                result = subprocess.check_output("wmic diskdrive get serialnumber", shell=True, text=True)
                lines = result.strip().split('\n')
                for line in lines[1:]:
                    if line.strip():
                        disk_serial = line.strip()
                        break
            except:
                disk_serial = "unknown"
        
        # Create unique HWID
        hwid_string = f"{system}-{machine}-{processor}-{mac_address}-{disk_serial}"
        hwid_hash = hashlib.sha256(hwid_string.encode()).hexdigest()[:16].upper()
        
        return hwid_hash
        
    except Exception as e:
        # Fallback HWID
        fallback = f"{platform.system()}-{platform.node()}-{platform.machine()}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:16].upper()

def get_public_ip():
    """Get user's public IP address"""
    try:
        services = [
            'https://api.ipify.org?format=text',
            'https://ipv4.icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
                
        return get_local_ip()
        
    except Exception:
        return "unknown"

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def send_discord_webhook(username, license_key, hwid, ip_address):
    """Send notification to Discord webhook"""
    if not Config.DISCORD_WEBHOOK_URL or 'YOUR_WEBHOOK_URL_HERE' in Config.DISCORD_WEBHOOK_URL:
        print(f"Discord webhook skipped (not configured)")
        return
    
    message = f"""🔐 **New Authentication Success**
**User:** {username}
**License:** {license_key}
**HWID:** {hwid}
**IP Address:** {ip_address}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"""
    
    payload = {"content": message}
    
    try:
        response = requests.post(Config.DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("✅ Discord notification sent")
        else:
            print(f"❌ Discord webhook failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Discord webhook error: {e}")

# Flask Application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize database on startup
Database()

# CORS headers for web requests
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Routes
@app.route('/', methods=['GET'])
def home():
    """Home page with API information"""
    return jsonify({
        'message': 'License Authentication System',
        'status': 'online',
        'endpoints': {
            'POST /register': 'Register new user',
            'POST /login': 'Login user', 
            'POST /activate-key': 'Activate license key',
            'POST /validate-key': 'Validate license',
            'POST /admin/generate-key': 'Generate license key',
            'GET /admin/stats': 'Get statistics',
            'GET /get-hwid': 'Get system HWID',
            'GET /health': 'Health check'
        }
    })

@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    
    # Validation
    if len(username) < 3 or len(password) < 6:
        return jsonify({'error': 'Username must be 3+ characters, password 6+ characters'}), 400
    
    user_id = User.create_user(username, password)
    
    if user_id:
        print(f"✅ New user registered: {username} (ID: {user_id})")
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user_id': user_id
        }), 201
    else:
        return jsonify({'error': 'Username already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    """Login user"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    user_id = User.verify_user(data['username'], data['password'])
    
    if user_id:
        print(f"✅ User login: {data['username']} (ID: {user_id})")
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user_id': user_id
        }), 200
    else:
        print(f"❌ Failed login attempt: {data['username']}")
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/activate-key', methods=['POST'])
def activate_key():
    """Activate a license key"""
    data = request.get_json()
    
    if not data or not all(key in data for key in ['user_id', 'license_key']):
        return jsonify({'error': 'user_id and license_key required'}), 400
    
    user_id = data['user_id']
    license_key = data['license_key']
    hwid = data.get('hwid') or get_hwid()
    
    # Verify user exists
    user = User.get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'Invalid user ID'}), 400
    
    success, message = License.activate_license(license_key, user_id, hwid)
    
    # Log the action
    ip_address = get_public_ip()
    Logger.log_action(user_id, license_key, hwid, ip_address, 'activation', success)
    
    if success:
        print(f"✅ License activated: {license_key} for user {user['username']}")
        return jsonify({
            'success': True,
            'message': message,
            'hwid': hwid
        }), 200
    else:
        print(f"❌ License activation failed: {message}")
        return jsonify({'error': message}), 400

@app.route('/validate-key', methods=['POST'])
def validate_key():
    """Validate a license key"""
    data = request.get_json()
    
    if not data or not data.get('license_key'):
        return jsonify({'error': 'license_key required'}), 400
    
    license_key = data['license_key']
    hwid = data.get('hwid') or get_hwid()
    ip_address = get_public_ip()
    
    is_valid, message, license_data = License.validate_license(license_key, hwid)
    
    if is_valid:
        # Log successful validation
        Logger.log_action(license_data['user_id'], license_key, hwid, ip_address, 'validation', True)
        
        # Send Discord notification
        send_discord_webhook(license_data['username'], license_key, hwid, ip_address)
        
        print(f"✅ Valid license check: {license_data['username']}")
        
        return jsonify({
            'success': True,
            'message': message,
            'user': license_data['username'],
            'expires_at': license_data['expires_at'],
            'hwid': hwid,
            'ip': ip_address
        }), 200
    else:
        # Log failed validation
        Logger.log_action(None, license_key, hwid, ip_address, 'validation', False)
        
        print(f"❌ Invalid license check: {message}")
        
        return jsonify({
            'success': False,
            'error': message,
            'hwid_detected': hwid
        }), 401

@app.route('/admin/generate-key', methods=['POST'])
def generate_key():
    """Generate a new license key (admin function)"""
    data = request.get_json() or {}
    expires_days = data.get('expires_days', 30)
    
    license_key = License.create_license(expires_days)
    
    print(f"🔑 New license generated: {license_key} ({expires_days} days)")
    
    return jsonify({
        'success': True,
        'license_key': license_key,
        'expires_days': expires_days,
        'expires_at': (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days else None
    }), 201

@app.route('/admin/stats', methods=['GET'])
def get_stats():
    """Get system statistics"""
    db = Database()
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Count users
    cursor.execute('SELECT COUNT(*) as count FROM users')
    user_count = cursor.fetchone()['count']
    
    # Count licenses
    cursor.execute('SELECT COUNT(*) as total, SUM(CASE WHEN user_id IS NOT NULL THEN 1 ELSE 0 END) as activated FROM licenses WHERE is_active = 1')
    license_stats = cursor.fetchone()
    
    # Recent validations (24 hours)
    cursor.execute('SELECT COUNT(*) as count FROM logs WHERE action = "validation" AND success = 1 AND timestamp > datetime("now", "-24 hours")')
    recent_validations = cursor.fetchone()['count']
    
    conn.close()
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'users': {
            'total': user_count
        },
        'licenses': {
            'total': license_stats['total'],
            'activated': license_stats['activated'],
            'available': license_stats['total'] - license_stats['activated']
        },
        'activity': {
            'validations_24h': recent_validations
        }
    }), 200

@app.route('/get-hwid', methods=['GET'])
def get_system_hwid():
    """Get system hardware ID and IP information"""
    hwid = get_hwid()
    public_ip = get_public_ip()
    local_ip = get_local_ip()
    
    return jsonify({
        'hwid': hwid,
        'public_ip': public_ip,
        'local_ip': local_ip,
        'system': platform.system(),
        'machine': platform.machine()
    }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0'
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Main application
if __name__ == '__main__':
    print("🚀 License Authentication System Starting...")
    print("=" * 60)
    print("📝 Available API Endpoints:")
    print("   POST /register          - Register new user")
    print("   POST /login             - User login")
    print("   POST /activate-key      - Activate license key")
    print("   POST /validate-key      - Validate license (main check)")
    print("   POST /admin/generate-key - Generate new license")
    print("   GET  /admin/stats       - System statistics") 
    print("   GET  /get-hwid          - Get hardware ID")
    print("   GET  /health            - Health check")
    print("   GET  /                  - API documentation")
    print("=" * 60)
    print("🔧 Configuration:")
    print(f"   Database: {Config.DATABASE_URL}")
    print(f"   Discord Webhook: {'✅ Configured' if 'YOUR_WEBHOOK_URL_HERE' not in Config.DISCORD_WEBHOOK_URL else '❌ Not configured'}")
    print("=" * 60)
    print("💡 Setup Instructions:")
    print("   1. Set DISCORD_WEBHOOK_URL environment variable")
    print("   2. Set SECRET_KEY environment variable for production")
    print("   3. Install: pip install Flask bcrypt requests psutil")
    print("=" * 60)
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    print(f"🌐 Server starting on port {port}...")
    print("✅ Ready for client connections!")
    
    # Run the Flask application
    app.run(
        debug=True,  # Set to False in production
        host='0.0.0.0',
        port=port
    )
