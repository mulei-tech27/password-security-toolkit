from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
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

app = Flask(__name__)
CORS(app)

COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "master", "welcome", "admin",
    "password123", "iloveyou", "sunshine", "princess",
    "shadow", "superman", "batman", "football", "123456789",
    "12345678", "1234567", "12345", "123123", "111111"
]

USERS_FILE = 'users.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ── Derive an AES encryption key from the master password ─
# Uses PBKDF2 with 200,000 rounds — extremely resistant to brute force
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=200000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# ── Encrypt vault data with Fernet (AES-128-CBC + HMAC) ──
def encrypt_vault(vault_data, master_password, username):
    salt      = f"vault-salt-{username}-v1"
    key       = derive_key(master_password, salt)
    f         = Fernet(key)
    json_bytes = json.dumps(vault_data).encode()
    return f.encrypt(json_bytes).decode()

# ── Decrypt vault data ────────────────────────────────────
def decrypt_vault(encrypted_data, master_password, username):
    salt = f"vault-salt-{username}-v1"
    key  = derive_key(master_password, salt)
    f    = Fernet(key)
    decrypted = f.decrypt(encrypted_data.encode())
    return json.loads(decrypted.decode())

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or len(username) < 3:
        return jsonify({ 'success': False, 'message': 'Username must be at least 3 characters.' })
    if len(password) < 8:
        return jsonify({ 'success': False, 'message': 'Master password must be at least 8 characters.' })
    users = load_users()
    if username in users:
        return jsonify({ 'success': False, 'message': 'Username already taken. Choose another.' })
    # Encrypt empty vault on registration
    encrypted_vault = encrypt_vault([], password, username)
    users[username] = {
        'password_hash':   hash_password(password),
        'vault_encrypted': encrypted_vault
    }
    save_users(users)
    return jsonify({ 'success': True, 'message': 'Account created! You can now log in.' })

@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'Username not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Incorrect password.' })
    return jsonify({ 'success': True, 'username': username, 'message': f'Welcome back, {username}!' })

@app.route('/api/vault/pin/set', methods=['POST'])
def set_vault_pin():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    pin      = data.get('pin', '')
    if not pin.isdigit() or len(pin) != 4:
        return jsonify({ 'success': False, 'message': 'PIN must be exactly 4 digits.' })
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'User not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Unauthorised.' })
    users[username]['vault_pin'] = hash_password(pin)
    save_users(users)
    return jsonify({ 'success': True, 'message': 'Vault PIN set successfully.' })

@app.route('/api/vault/pin/verify', methods=['POST'])
def verify_vault_pin():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    pin      = data.get('pin', '')
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'User not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Unauthorised.' })
    stored_pin = users[username].get('vault_pin')
    if not stored_pin:
        return jsonify({ 'success': False, 'has_pin': False, 'message': 'No PIN set yet.' })
    if stored_pin != hash_password(pin):
        return jsonify({ 'success': False, 'has_pin': True, 'message': 'Incorrect PIN.' })
    return jsonify({ 'success': True, 'message': 'PIN verified.' })

@app.route('/api/vault/save', methods=['POST'])
def save_vault():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    vault    = data.get('vault', [])
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'User not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Unauthorised.' })
    # Encrypt vault before saving — plain text never touches disk
    users[username]['vault_encrypted'] = encrypt_vault(vault, password, username)
    # Remove old unencrypted vault if it exists
    users[username].pop('vault', None)
    save_users(users)
    return jsonify({ 'success': True })

@app.route('/api/vault/load', methods=['POST'])
def load_vault():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'User not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Unauthorised.' })
    has_pin = 'vault_pin' in users[username]
    try:
        # Decrypt vault using master password
        encrypted = users[username].get('vault_encrypted')
        if encrypted:
            vault = decrypt_vault(encrypted, password, username)
        else:
            vault = []
    except Exception:
        vault = []
    return jsonify({ 'success': True, 'vault': vault, 'has_pin': has_pin })

@app.route('/api/delete-account', methods=['POST'])
def delete_account():
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    users = load_users()
    if username not in users:
        return jsonify({ 'success': False, 'message': 'User not found.' })
    if users[username]['password_hash'] != hash_password(password):
        return jsonify({ 'success': False, 'message': 'Incorrect password.' })
    del users[username]
    save_users(users)
    return jsonify({ 'success': True, 'message': 'Account deleted.' })

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
    app.run(debug=True)