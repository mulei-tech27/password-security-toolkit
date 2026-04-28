from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import hashlib
import requests
import json
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
CORS(app)

# ── Rate Limiter — brute force protection ─────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "welcome", "admin",
    "password123", "iloveyou", "sunshine", "princess",
    "shadow", "superman", "batman", "football", "123456789",
    "12345678", "1234567", "12345", "123123", "111111"
]

# ── PostgreSQL connection ─────────────────────────────────
def get_db():
    conn = psycopg2.connect(
        os.environ.get('DATABASE_URL'),
        cursor_factory=RealDictCursor
    )
    return conn

# ── Create tables if they don't exist ────────────────────
def init_db():
    conn = get_db()
    cur  = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id               SERIAL PRIMARY KEY,
            username         VARCHAR(50) UNIQUE NOT NULL,
            password_hash    VARCHAR(64) NOT NULL,
            vault_encrypted  TEXT,
            vault_pin        VARCHAR(64),
            login_attempts   INTEGER DEFAULT 0,
            locked_until     TIMESTAMP,
            created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

# Run on startup
with app.app_context():
    init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ── Derive AES key from master password ──────────────────
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=200000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_vault(vault_data, master_password, username):
    salt = f"vault-salt-{username}-v1"
    key  = derive_key(master_password, salt)
    f    = Fernet(key)
    return f.encrypt(json.dumps(vault_data).encode()).decode()

def decrypt_vault(encrypted_data, master_password, username):
    salt = f"vault-salt-{username}-v1"
    key  = derive_key(master_password, salt)
    f    = Fernet(key)
    return json.loads(f.decrypt(encrypted_data.encode()).decode())

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

# ── Register ──────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or len(username) < 3:
        return jsonify({ 'success': False, 'message': 'Username must be at least 3 characters.' })
    if len(password) < 8:
        return jsonify({ 'success': False, 'message': 'Master password must be at least 8 characters.' })
    try:
        conn = get_db()
        cur  = conn.cursor()
        # Check if username exists
        cur.execute('SELECT id FROM users WHERE username = %s', (username,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Username already taken. Choose another.' })
        # Create user with empty encrypted vault
        encrypted_vault = encrypt_vault([], password, username)
        cur.execute(
            'INSERT INTO users (username, password_hash, vault_encrypted) VALUES (%s, %s, %s)',
            (username, hash_password(password), encrypted_vault)
        )
        conn.commit()
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'message': 'Account created! You can now log in.' })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Login — max 5 attempts then locked for 15 minutes ────
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user:
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Username not found.' })

        # Check if account is locked
        if user['locked_until']:
            from datetime import datetime
            if datetime.utcnow() < user['locked_until']:
                mins = int((user['locked_until'] - datetime.utcnow()).seconds / 60) + 1
                cur.close(); conn.close()
                return jsonify({ 'success': False, 'message': f'Account locked. Try again in {mins} minute(s).' })
            else:
                # Reset lock
                cur.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = %s', (username,))
                conn.commit()

        # Check password
        if user['password_hash'] != hash_password(password):
            attempts = user['login_attempts'] + 1
            if attempts >= 5:
                # Lock account for 15 minutes
                cur.execute('''
                    UPDATE users SET login_attempts = %s,
                    locked_until = CURRENT_TIMESTAMP + INTERVAL '15 minutes'
                    WHERE username = %s
                ''', (attempts, username))
                conn.commit()
                cur.close(); conn.close()
                return jsonify({ 'success': False, 'message': f'Too many failed attempts. Account locked for 15 minutes.' })
            else:
                cur.execute('UPDATE users SET login_attempts = %s WHERE username = %s', (attempts, username))
                conn.commit()
                remaining = 5 - attempts
                cur.close(); conn.close()
                return jsonify({ 'success': False, 'message': f'Incorrect password. {remaining} attempt(s) remaining.' })

        # Successful login — reset attempts
        cur.execute('UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = %s', (username,))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'username': username, 'message': f'Welcome back, {username}!' })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Set vault PIN ─────────────────────────────────────────
@app.route('/api/vault/pin/set', methods=['POST'])
@limiter.limit("10 per hour")
def set_vault_pin():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    pin      = data.get('pin', '')
    if not pin.isdigit() or len(pin) != 4:
        return jsonify({ 'success': False, 'message': 'PIN must be exactly 4 digits.' })
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user or user['password_hash'] != hash_password(password):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Unauthorised.' })
        cur.execute('UPDATE users SET vault_pin = %s WHERE username = %s', (hash_password(pin), username))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'message': 'Vault PIN set successfully.' })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Verify vault PIN — max 5 attempts ────────────────────
@app.route('/api/vault/pin/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify_vault_pin():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    pin      = data.get('pin', '')
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT password_hash, vault_pin FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user or user['password_hash'] != hash_password(password):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Unauthorised.' })
        if not user['vault_pin']:
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'has_pin': False, 'message': 'No PIN set yet.' })
        if user['vault_pin'] != hash_password(pin):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'has_pin': True, 'message': 'Incorrect PIN.' })
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'message': 'PIN verified.' })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Save vault ────────────────────────────────────────────
@app.route('/api/vault/save', methods=['POST'])
def save_vault():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    vault    = data.get('vault', [])
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user or user['password_hash'] != hash_password(password):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Unauthorised.' })
        encrypted = encrypt_vault(vault, password, username)
        cur.execute('UPDATE users SET vault_encrypted = %s WHERE username = %s', (encrypted, username))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({ 'success': True })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Load vault ────────────────────────────────────────────
@app.route('/api/vault/load', methods=['POST'])
def load_vault():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT password_hash, vault_encrypted, vault_pin FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user or user['password_hash'] != hash_password(password):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Unauthorised.' })
        has_pin = user['vault_pin'] is not None
        try:
            vault = decrypt_vault(user['vault_encrypted'], password, username) if user['vault_encrypted'] else []
        except Exception:
            vault = []
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'vault': vault, 'has_pin': has_pin })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Delete account ────────────────────────────────────────
@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        if not user or user['password_hash'] != hash_password(password):
            cur.close(); conn.close()
            return jsonify({ 'success': False, 'message': 'Incorrect password.' })
        cur.execute('DELETE FROM users WHERE username = %s', (username,))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({ 'success': True, 'message': 'Account deleted.' })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Server error: {str(e)}' })

# ── Password check ────────────────────────────────────────
@app.route('/api/check', methods=['POST'])
def check_password():
    data     = request.get_json()
    password = data.get('password', '')
    score    = 0
    feedback = []
    checks   = {}
    checks['len'] = len(password) >= 8
    if checks['len']: score += 1
    else: feedback.append("Use at least 8 characters")
    checks['upper'] = bool(re.search(r'[A-Z]', password))
    if checks['upper']: score += 1
    else: feedback.append("Add an uppercase letter (A-Z)")
    checks['lower'] = bool(re.search(r'[a-z]', password))
    if checks['lower']: score += 1
    else: feedback.append("Add a lowercase letter (a-z)")
    checks['num'] = bool(re.search(r'[0-9]', password))
    if checks['num']: score += 1
    else: feedback.append("Add a number (0-9)")
    checks['sym'] = bool(re.search(r'[!@#$%^&*()_+\-=]', password))
    if checks['sym']: score += 1
    else: feedback.append("Add a symbol like !@#$%")
    checks['common'] = password.lower() not in COMMON_PASSWORDS
    if checks['common']: score += 1
    else: feedback.append("This is a very common password!")
    strength = "Weak" if score<=2 else "Fair" if score<=3 else "Good" if score<=4 else "Strong"
    return jsonify({ 'score': score, 'strength': strength, 'checks': checks, 'feedback': feedback })

# ── Password generator ────────────────────────────────────
@app.route('/api/generate', methods=['POST'])
def generate_password():
    data     = request.get_json()
    name     = data.get('name', '').lower()
    birth    = data.get('birth', '').lower()
    hobby    = data.get('hobby', '').lower()
    pet      = data.get('pet', '').lower()
    personal = [x for x in [name, birth, hobby, pet] if x]
    warnings = []
    if name:  warnings.append(f'"{name}" — your name is the first thing a hacker searches')
    if birth: warnings.append(f'"{birth}" — birth years are in top 10 password guesses')
    if hobby: warnings.append(f'"{hobby}" — hobbies are findable on your social media')
    if pet:   warnings.append(f'"{pet}" — pet names are a classic social engineering target')
    import random, string
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    numbers = string.digits
    symbols = '!@#$%^&*()_+-='
    all_ch  = lower + upper + numbers + symbols
    while True:
        pw = (
            [random.choice(lower)   for _ in range(3)] +
            [random.choice(upper)   for _ in range(3)] +
            [random.choice(numbers) for _ in range(3)] +
            [random.choice(symbols) for _ in range(3)] +
            [random.choice(all_ch)  for _ in range(4)]
        )
        random.shuffle(pw)
        pw = ''.join(pw)
        if not any(word in pw.lower() for word in personal if word):
            break
    return jsonify({ 'password': pw, 'warnings': warnings })

# ── Breach check ──────────────────────────────────────────
@app.route('/api/breach', methods=['POST'])
def check_breach():
    data     = request.get_json()
    password = data.get('password', '')
    sha1     = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix   = sha1[:5]
    suffix   = sha1[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        count = 0
        for line in response.text.splitlines():
            h, t = line.split(':')
            if h.strip() == suffix:
                count = int(t.strip())
                break
        if count > 0:
            return jsonify({ 'breached': True, 'count': count, 'message': f'Found in {count:,} breaches!' })
        else:
            return jsonify({ 'breached': False, 'count': 0, 'message': 'Not found in any known breaches.' })
    except Exception as e:
        return jsonify({ 'breached': None, 'message': 'Could not connect to breach database.' })

if __name__ == '__main__':
    init_db()
    app.run(debug=True)