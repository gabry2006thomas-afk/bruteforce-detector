import os
import sqlite3
import bcrypt
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps

# ── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'database.db')
LOG_PATH = os.path.join(BASE_DIR, 'logs', 'security.log')

os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# ── Security Config ────────────────────────────────────────────────────────────
MAX_ATTEMPTS    = 5          # failed attempts before block
ATTEMPT_WINDOW  = 10         # minutes to look back
BLOCK_DURATION  = 15         # minutes to block

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def sec_log(level, event, details):
    msg = f"[{event}] {json.dumps(details)}"
    getattr(logger, level)(msg)

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status     TEXT NOT NULL,
                reason     TEXT,
                timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS blocked_entities (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                entity      TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                unblock_at  DATETIME NOT NULL,
                reason      TEXT
            );
        """)
    logger.info("[SYSTEM] Database initialized")

# ── Helper: get real IP ────────────────────────────────────────────────────────
def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

# ── Block Checks ───────────────────────────────────────────────────────────────
def is_blocked(entity, entity_type):
    """Check if IP or email is currently blocked."""
    with get_db() as db:
        row = db.execute(
            "SELECT unblock_at FROM blocked_entities "
            "WHERE entity=? AND entity_type=? AND unblock_at > datetime('now') "
            "ORDER BY blocked_at DESC LIMIT 1",
            (entity, entity_type)
        ).fetchone()
    if row:
        unblock_at = datetime.fromisoformat(row['unblock_at'])
        remaining  = max(0, int((unblock_at - datetime.utcnow()).total_seconds() // 60))
        return True, remaining
    return False, 0

def block_entity(entity, entity_type, reason):
    unblock_at = datetime.utcnow() + timedelta(minutes=BLOCK_DURATION)
    with get_db() as db:
        db.execute(
            "INSERT INTO blocked_entities (entity, entity_type, unblock_at, reason) VALUES (?,?,?,?)",
            (entity, entity_type, unblock_at.isoformat(), reason)
        )
    sec_log('warning', 'BLOCKED', {'entity': entity, 'type': entity_type, 'reason': reason,
                                    'unblock_at': unblock_at.isoformat()})

# ── Brute-Force Detection ──────────────────────────────────────────────────────
def count_recent_failures(email, ip):
    window_start = (datetime.utcnow() - timedelta(minutes=ATTEMPT_WINDOW)).isoformat()
    with get_db() as db:
        by_email = db.execute(
            "SELECT COUNT(*) as c FROM login_attempts "
            "WHERE email=? AND status='failed' AND timestamp > ?",
            (email, window_start)
        ).fetchone()['c']
        by_ip = db.execute(
            "SELECT COUNT(*) as c FROM login_attempts "
            "WHERE ip_address=? AND status='failed' AND timestamp > ?",
            (ip, window_start)
        ).fetchone()['c']
    return by_email, by_ip

def record_attempt(email, ip, status, reason=None):
    with get_db() as db:
        db.execute(
            "INSERT INTO login_attempts (email, ip_address, status, reason) VALUES (?,?,?,?)",
            (email, ip, status, reason)
        )

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/admin')
def admin():
    if 'user' not in session:
        return redirect(url_for('login_page'))
    return render_template('admin.html')

# ── API: Register ──────────────────────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def api_register():
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    pwd   = data.get('password') or ''

    if not email or not pwd:
        return jsonify({'error': 'Email and password are required.'}), 400
    if '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({'error': 'Invalid email address.'}), 400
    if len(pwd) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (email, password) VALUES (?,?)", (email, hashed))
        sec_log('info', 'REGISTER', {'email': email, 'ip': get_ip()})
        return jsonify({'message': 'Account created successfully.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An account with this email already exists.'}), 409
    except Exception as e:
        logger.error(f"[REGISTER_ERROR] {e}")
        return jsonify({'error': 'Registration failed. Please try again.'}), 500

# ── API: Login ─────────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    data  = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    pwd   = data.get('password') or ''
    ip    = get_ip()

    if not email or not pwd:
        return jsonify({'error': 'Email and password are required.'}), 400

    # ── Check IP block ──
    ip_blocked, ip_remaining = is_blocked(ip, 'ip')
    if ip_blocked:
        sec_log('warning', 'BLOCKED_ATTEMPT', {'email': email, 'ip': ip, 'reason': 'ip_blocked'})
        return jsonify({
            'error': f'Your IP is temporarily blocked due to suspicious activity. Try again in {ip_remaining} minute(s).',
            'blocked': True, 'remaining_minutes': ip_remaining
        }), 429

    # ── Check email block ──
    em_blocked, em_remaining = is_blocked(email, 'email')
    if em_blocked:
        sec_log('warning', 'BLOCKED_ATTEMPT', {'email': email, 'ip': ip, 'reason': 'email_blocked'})
        return jsonify({
            'error': f'This account is temporarily locked. Try again in {em_remaining} minute(s).',
            'blocked': True, 'remaining_minutes': em_remaining
        }), 429

    # ── Verify credentials ──
    try:
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    except Exception as e:
        logger.error(f"[LOGIN_DB_ERROR] {e}")
        return jsonify({'error': 'An internal error occurred.'}), 500

    if not user or not bcrypt.checkpw(pwd.encode(), user['password'].encode()):
        # Failed login
        record_attempt(email, ip, 'failed', 'invalid_credentials')
        sec_log('warning', 'LOGIN_FAILED', {'email': email, 'ip': ip})

        by_email, by_ip = count_recent_failures(email, ip)

        # Check thresholds AFTER recording this attempt
        if by_email >= MAX_ATTEMPTS:
            block_entity(email, 'email', f'{by_email} failed attempts in {ATTEMPT_WINDOW}m')
            return jsonify({
                'error': f'Account locked after {MAX_ATTEMPTS} failed attempts. Try again in {BLOCK_DURATION} minutes.',
                'blocked': True, 'remaining_minutes': BLOCK_DURATION
            }), 429

        if by_ip >= MAX_ATTEMPTS:
            block_entity(ip, 'ip', f'{by_ip} failed attempts from this IP in {ATTEMPT_WINDOW}m')
            return jsonify({
                'error': f'IP blocked after {MAX_ATTEMPTS} failed attempts. Try again in {BLOCK_DURATION} minutes.',
                'blocked': True, 'remaining_minutes': BLOCK_DURATION
            }), 429

        attempts_left = max(0, MAX_ATTEMPTS - by_email)
        return jsonify({
            'error': 'Invalid email or password.',
            'attempts_left': attempts_left,
            'warning': attempts_left <= 2
        }), 401

    # ── Successful login ──
    record_attempt(email, ip, 'success')
    sec_log('info', 'LOGIN_SUCCESS', {'email': email, 'ip': ip})
    session['user'] = email
    return jsonify({'message': 'Login successful.', 'email': email}), 200

# ── API: Logout ────────────────────────────────────────────────────────────────
@app.route('/api/logout', methods=['POST'])
def api_logout():
    email = session.pop('user', None)
    if email:
        sec_log('info', 'LOGOUT', {'email': email, 'ip': get_ip()})
    return jsonify({'message': 'Logged out.'}), 200

# ── API: Admin Stats ───────────────────────────────────────────────────────────
@app.route('/api/admin/stats', methods=['GET'])
def admin_stats():
    with get_db() as db:
        total_users    = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
        total_attempts = db.execute("SELECT COUNT(*) as c FROM login_attempts").fetchone()['c']
        failed_attempts= db.execute("SELECT COUNT(*) as c FROM login_attempts WHERE status='failed'").fetchone()['c']
        success_attempts=db.execute("SELECT COUNT(*) as c FROM login_attempts WHERE status='success'").fetchone()['c']
        active_blocks  = db.execute(
            "SELECT COUNT(*) as c FROM blocked_entities WHERE unblock_at > datetime('now')"
        ).fetchone()['c']

        recent_attempts = db.execute(
            "SELECT email, ip_address, status, reason, timestamp "
            "FROM login_attempts ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()

        blocked_list = db.execute(
            "SELECT entity, entity_type, blocked_at, unblock_at, reason "
            "FROM blocked_entities WHERE unblock_at > datetime('now') ORDER BY blocked_at DESC"
        ).fetchall()

        # Top attacking IPs
        top_ips = db.execute(
            "SELECT ip_address, COUNT(*) as c FROM login_attempts "
            "WHERE status='failed' GROUP BY ip_address ORDER BY c DESC LIMIT 10"
        ).fetchall()

        # Attempts per hour (last 24h)
        hourly = db.execute(
            "SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as c "
            "FROM login_attempts "
            "WHERE timestamp > datetime('now', '-24 hours') "
            "GROUP BY hour ORDER BY hour"
        ).fetchall()

    return jsonify({
        'stats': {
            'total_users': total_users,
            'total_attempts': total_attempts,
            'failed_attempts': failed_attempts,
            'success_attempts': success_attempts,
            'active_blocks': active_blocks,
        },
        'recent_attempts': [dict(r) for r in recent_attempts],
        'blocked_list': [dict(r) for r in blocked_list],
        'top_ips': [dict(r) for r in top_ips],
        'hourly_activity': [dict(r) for r in hourly],
    })

# ── API: Simulate Brute Force (for demo) ──────────────────────────────────────
@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Inject fake failed attempts to demonstrate detection."""
    data   = request.get_json(silent=True) or {}
    target = data.get('target_email', 'victim@example.com')
    count  = min(int(data.get('count', 6)), 20)
    fake_ip= data.get('ip', '192.168.99.99')
    ts_now = datetime.utcnow()

    with get_db() as db:
        for i in range(count):
            ts = (ts_now - timedelta(seconds=i * 30)).isoformat()
            db.execute(
                "INSERT INTO login_attempts (email, ip_address, status, reason, timestamp) VALUES (?,?,?,?,?)",
                (target, fake_ip, 'failed', 'simulated_brute_force', ts)
            )
    sec_log('warning', 'SIMULATION', {'target': target, 'count': count, 'fake_ip': fake_ip})
    return jsonify({'message': f'Injected {count} simulated failed attempts for {target}.'})

# ── Boot ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print("\n🛡️  Brute Force Detection System running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
