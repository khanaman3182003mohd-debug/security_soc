"""SOAR Sentinel: local analyst workspace, not a live response engine."""
import hmac
import os
import re
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

SEVERITIES = ('Low', 'Medium', 'High', 'Critical')
STATUSES = ('Open', 'Investigating', 'Resolved')
PLAYBOOKS = {
    'login-abuse': {'name': 'Failed login investigation',
                    'description': 'Review possible credential abuse without locking accounts.',
                    'steps': ['Collect authentication events and preserve timestamps.',
                              'Compare source addresses, device identity and user baseline.',
                              'Confirm suspicious activity with the account owner.',
                              'Request human approval before any credential or access change.']},
    'endpoint-triage': {'name': 'Suspicious endpoint triage',
                       'description': 'Preserve evidence and scope suspicious process activity.',
                       'steps': ['Preserve the alert and process tree.',
                                 'Review command lines, signatures and parent processes.',
                                 'Scope related indicators across available logs.',
                                 'Escalate evidence to an analyst; do not isolate automatically.']},
    'network-review': {'name': 'Outbound traffic review',
                       'description': 'Assess unusual traffic with a review-first workflow.',
                       'steps': ['Record destination, port, volume and time window.',
                                 'Compare with the device network baseline.',
                                 'Correlate DNS and endpoint telemetry.',
                                 'Document findings and obtain approval before blocking.']}}


OBSERVABLE_KINDS = ('IPv4', 'Domain', 'URL', 'Email', 'SHA-256', 'MD5', 'Other')
# Documentation-range "bad" values (RFC 5737/3849) used only by the simulated feed.
SIMULATED_BAD_IPS = {'203.0.113.9', '198.51.100.7'}
SIMULATED_BAD_DOMAINS = {'login-secure-alert.zip', 'mail-verify.update-now.zip'}
SIMULATED_BAD_TLDS = ('.zip', '.review', '.country')
IOC_PATTERNS = (
    ('SHA-256', re.compile(r'\b[a-fA-F0-9]{64}\b')),
    ('MD5', re.compile(r'\b[a-fA-F0-9]{32}\b')),
    ('URL', re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)),
    ('Email', re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ('IPv4', re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')),
    ('Domain', re.compile(r'\b(?=.{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b')),
)


def is_private_ip(value):
    try:
        parts = [int(p) for p in value.split('.')]
    except ValueError:
        return False
    if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
        return False
    first, second = parts[0], parts[1]
    return (first == 10 or first == 127 or (first == 172 and 16 <= second <= 31)
            or (first == 192 and second == 168))


def enrich(kind, value):
    """Return (verdict, context) from a LOCAL simulated feed. No live lookups."""
    text = value.lower()
    if kind == 'IPv4':
        if is_private_ip(value):
            return 'Internal', 'Private address space — not externally reachable (simulated).'
        if value in SIMULATED_BAD_IPS:
            return 'Malicious', 'Matches the local simulated blocklist (not a live feed).'
        return 'Unknown', 'No local reputation — manual review required.'
    if kind in ('SHA-256', 'MD5'):
        return 'Unknown', 'File hash captured; no live sandbox or reputation (simulated).'
    if kind == 'Domain':
        if text in SIMULATED_BAD_DOMAINS or any(text.endswith(t) for t in SIMULATED_BAD_TLDS):
            return 'Malicious', 'Matches the local simulated blocklist (not a live feed).'
        return 'Unknown', 'No local reputation — manual review required.'
    if kind == 'Email':
        return 'Unknown', 'Sender captured; verify with the reporting user (simulated).'
    if kind == 'URL':
        return 'Unknown', 'URL captured; do not open from production hosts (simulated).'
    return 'Unknown', 'No enrichment available for this indicator type.'


def extract_iocs(text):
    """Regex-based indicator extraction (the automation 'bot'). No external calls."""
    found, seen = [], set()
    for kind, pattern in IOC_PATTERNS:
        for match in pattern.findall(text or ''):
            token = (kind, match.lower())
            if token not in seen:
                seen.add(token)
                found.append({'kind': kind, 'value': match})
    return found


def suggest_playbook(text):
    body = (text or '').lower()
    if any(w in body for w in ('password', 'login', 'credential', 'sign-in', 'failed auth', 'mfa')):
        return 'login-abuse'
    if any(w in body for w in ('powershell', 'process', 'malware', 'endpoint', 'ransom', 'exe', 'beacon')):
        return 'endpoint-triage'
    if any(w in body for w in ('outbound', 'dns', 'traffic', 'connection', 'exfil', 'upload')):
        return 'network-review'
    return None


def priority_for(severity, iocs):
    base = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4}.get(severity, 3)
    if any(enrich(i['kind'], i['value'])[0] == 'Malicious' for i in iocs):
        return min(base, 1)
    return base


def safe_next(value, fallback):
    """Allow only same-origin relative redirects (block open redirects)."""
    if value and value.startswith('/') and not value.startswith('//'):
        return value
    return fallback


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def find_available_port(start_port=5000, max_port=5100):
    """Return the first free local port in the configured range."""
    for port in range(start_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                continue
            return port
    raise RuntimeError(f'No free ports available between {start_port} and {max_port}.')


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get('SOAR_DB_PATH') or str(Path(app.instance_path) / 'soar.db'),
        SECRET_KEY=os.environ.get('SECRET_KEY') or os.environ.get('SOAR_SECRET_KEY'),
        GOOGLE_CLIENT_ID=os.environ.get('GOOGLE_CLIENT_ID'),
        GOOGLE_CLIENT_SECRET=os.environ.get('GOOGLE_CLIENT_SECRET'),
        ALLOW_REGISTRATION=os.environ.get('ALLOW_REGISTRATION', '1') == '1',
        DEFAULT_ROLE='viewer',
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('SOAR_HTTPS') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False, MAX_CONTENT_LENGTH=32 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config['SECRET_KEY']:
        key_path = Path(app.instance_path) / 'session.key'
        try:
            with key_path.open('x', encoding='utf-8') as handle:
                handle.write(secrets.token_hex(32))
            key_path.chmod(0o600)
        except FileExistsError:
            pass
        app.config['SECRET_KEY'] = key_path.read_text(encoding='utf-8').strip()

    # Google OAuth (only active when client id/secret are provided)
    oauth = OAuth(app)
    if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={'scope': 'openid email profile'},
        )
        app.config['GOOGLE_ENABLED'] = True
    else:
        app.config['GOOGLE_ENABLED'] = False
    token_path = Path(app.instance_path) / 'ingest.token'
    app.config['INGEST_TOKEN'] = os.environ.get('SOAR_INGEST_TOKEN')
    if not app.config['INGEST_TOKEN']:
        try:
            with token_path.open('x', encoding='utf-8') as handle:
                handle.write(secrets.token_hex(16))
            token_path.chmod(0o600)
        except FileExistsError:
            pass
        app.config['INGEST_TOKEN'] = token_path.read_text(encoding='utf-8').strip()

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'], timeout=10)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop('db', None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'Medium', source TEXT NOT NULL DEFAULT 'Manual',
                status TEXT NOT NULL DEFAULT 'Open', details TEXT DEFAULT '', created_at TEXT NOT NULL,
                assignee TEXT DEFAULT '', playbook TEXT DEFAULT '', priority INTEGER DEFAULT 3,
                updated_at TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                email TEXT DEFAULT '', google_id TEXT DEFAULT '',
                must_change_password INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
                address TEXT NOT NULL, attempted_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS attempts_time ON login_attempts(attempted_at);
           CREATE TABLE IF NOT EXISTS observables (
               id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
               kind TEXT NOT NULL, value TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT 'Unknown',
               context TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, actor TEXT NOT NULL);
           CREATE INDEX IF NOT EXISTS observables_incident ON observables(incident_id);
           CREATE TABLE IF NOT EXISTS notes (
               id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
               author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL);
           CREATE INDEX IF NOT EXISTS notes_incident ON notes(incident_id);
           CREATE TABLE IF NOT EXISTS approvals (
               id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
               action TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending',
               decided_by TEXT, decided_at TEXT, created_at TEXT NOT NULL);
           CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status);
        ''')
        db().commit()

    def _migrate_users_table():
        """Add columns to an existing users table from an older schema version."""
        existing = {row['name'] for row in db().execute('PRAGMA table_info(users)').fetchall()}
        for column, ddl in (('email', "TEXT DEFAULT ''"), ('google_id', "TEXT DEFAULT ''"),
                            ('must_change_password', 'INTEGER NOT NULL DEFAULT 0')):
            if column not in existing:
                db().execute('ALTER TABLE users ADD COLUMN ' + column + ' ' + ddl)
        db().commit()
    with app.app_context():
        _migrate_users_table()

    def audit(action, details, actor=None):
        db().execute('INSERT INTO audit(created_at,actor,action,details) VALUES(?,?,?,?)',
                     (now(), actor or (g.user['username'] if g.user else 'anonymous'), action, details))

    def csrf_token():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_hex(32)
        return session['csrf']

    @app.context_processor
    def context():
        pending = 0
        try:
            pending = db().execute("SELECT COUNT(*) FROM approvals WHERE status='Pending'").fetchone()[0]
        except sqlite3.OperationalError:
            pending = 0
        return {'user': g.user, 'csrf_token': csrf_token, 'pending_approvals': pending,
                'google_enabled': app.config['GOOGLE_ENABLED'],
                'allow_registration': app.config['ALLOW_REGISTRATION']}

    @app.before_request
    def protect():
        g.user = None
        if session.get('user_id'):
            g.user = db().execute('SELECT * FROM users WHERE id=? AND active=1',
                                  (session['user_id'],)).fetchone()
            if not g.user:
                session.clear()
        if request.method == 'POST' and request.path != '/api/ingest':
            token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
            if not token or not hmac.compare_digest(session.get('csrf', ''), token):
                abort(400, description='Security token expired or missing. Reload the page and try again.')

    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cache-Control'] = 'no-store'
        if app.config['SESSION_COOKIE_SECURE']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    def require(*roles):
        def decorator(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                if not g.user:
                    if request.path.startswith('/api/'):
                        abort(401)
                    return redirect(url_for('login'))
                if roles and g.user['role'] not in roles:
                    abort(403)
                return function(*args, **kwargs)
            return wrapped
        return decorator

    def metrics():
        rows = db().execute('SELECT status, severity FROM incidents').fetchall()
        return {'total': len(rows), 'open': sum(r['status'] == 'Open' for r in rows),
                'investigating': sum(r['status'] == 'Investigating' for r in rows),
                'resolved': sum(r['status'] == 'Resolved' for r in rows),
                'critical': sum(r['severity'] == 'Critical' for r in rows)}

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if g.user:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip().lower()[:80]
            password = request.form.get('password', '')
            address = request.remote_addr or 'unknown'
            timestamp = time.time()
            db().execute('DELETE FROM login_attempts WHERE attempted_at < ?', (timestamp - 900,))
            count = db().execute('SELECT COUNT(*) FROM login_attempts WHERE username=? OR address=?',
                                 (username, address)).fetchone()[0]
            if count >= 5:
                db().commit()
                abort(429, description='Too many login attempts. Try again in 15 minutes.')
            account = db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            valid = check_password_hash(account['password_hash'] if account else dummy_hash, password)
            if account and account['active'] and valid:
                session.clear()
                session.permanent = True
                session['user_id'] = account['id']
                audit('login', 'Successful sign-in', username)
                db().commit()
                return redirect(url_for('dashboard'))
            db().execute('INSERT INTO login_attempts(username,address,attempted_at) VALUES(?,?,?)',
                         (username, address, timestamp))
            audit('login_failed', 'Invalid sign-in', username or 'anonymous')
            db().commit()
            flash('Invalid username or password.', 'error')
        return render_template('login.html')

    dummy_hash = generate_password_hash(secrets.token_hex(32))

    @app.post('/logout')
    @require()
    def logout():
        audit('logout', 'Signed out')
        db().commit()
        session.clear()
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if g.user:
            return redirect(url_for('dashboard'))
        if not app.config['ALLOW_REGISTRATION']:
            flash('New account registration is currently disabled.', 'error')
            return redirect(url_for('login'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip().lower()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm = request.form.get('confirm', '')
            if password != confirm:
                flash('Passwords do not match.', 'error')
            else:
                try:
                    insert_user(username, password, app.config['DEFAULT_ROLE'], email)
                    audit('register', f'New self-registered account: {username}', username)
                    db().commit()
                    flash('Account created. You can now sign in.', 'success')
                    return redirect(url_for('login'))
                except (ValueError, sqlite3.IntegrityError) as error:
                    db().rollback()
                    flash(str(error) if isinstance(error, ValueError)
                         else 'That username or email is already taken.', 'error')
        return render_template('register.html')

    @app.route('/account/password', methods=['GET', 'POST'])
    @require()
    def change_password():
        if request.method == 'POST':
            current = request.form.get('current', '')
            new = request.form.get('new', '')
            confirm = request.form.get('confirm', '')
            account = db().execute('SELECT * FROM users WHERE id=?', (g.user['id'],)).fetchone()
            if not check_password_hash(account['password_hash'], current):
                flash('Your current password is incorrect.', 'error')
            elif new != confirm:
                flash('New passwords do not match.', 'error')
            elif not 12 <= len(new) <= 128:
                flash('Use a password of 12–128 characters.', 'error')
            elif check_password_hash(account['password_hash'], new):
                flash('Choose a password different from your current one.', 'error')
            else:
                db().execute('UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?',
                             (generate_password_hash(new), g.user['id']))
                audit('password_changed', 'User updated their own password')
                db().commit()
                flash('Password updated successfully.', 'success')
                return redirect(url_for('dashboard'))
        return render_template('change_password.html')

    @app.get('/login/google')
    def google_login():
        if not app.config['GOOGLE_ENABLED']:
            flash('Google sign-in is not configured on this server.', 'error')
            return redirect(url_for('login'))
        redirect_uri = url_for('google_callback', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.get('/login/google/callback')
    def google_callback():
        if not app.config['GOOGLE_ENABLED']:
            return redirect(url_for('login'))
        try:
            token = oauth.google.authorize_access_token()
            userinfo = token.get('userinfo') or oauth.google.parse_id_token(token, nonce=session.pop('google_nonce', None))
        except Exception:
            flash('Google sign-in failed. Please try again.', 'error')
            return redirect(url_for('login'))
        email = (userinfo.get('email') or '').strip().lower()
        google_id = str(userinfo.get('sub') or '')
        if not email or not google_id:
            flash('Google did not return a verified email.', 'error')
            return redirect(url_for('login'))
        account = db().execute('SELECT * FROM users WHERE google_id=? OR email=?',
                               (google_id, email)).fetchone()
        if account and not account['google_id']:
            db().execute('UPDATE users SET google_id=? WHERE id=?', (google_id, account['id']))
        if not account:
            base = email.split('@')[0]
            username = re.sub(r'[^A-Za-z0-9._-]', '', base)[:40] or 'user'
            candidate, suffix = username, 1
            while db().execute('SELECT 1 FROM users WHERE username=?', (candidate,)).fetchone():
                candidate = f'{username}{suffix}'
                suffix += 1
            db().execute('INSERT INTO users(username,password_hash,role,email,google_id) VALUES(?,?,?,?,?)',
                         (candidate, generate_password_hash(secrets.token_hex(16)),
                          app.config['DEFAULT_ROLE'], email, google_id))
            account = db().execute('SELECT * FROM users WHERE google_id=?', (google_id,)).fetchone()
            audit('register', f'Account created via Google: {candidate}', candidate)
        if not account['active']:
            flash('This account has been disabled. Contact an administrator.', 'error')
            db().commit()
            return redirect(url_for('login'))
        session.clear()
        session.permanent = True
        session['user_id'] = account['id']
        audit('login', 'Successful sign-in via Google', account['username'])
        db().commit()
        return redirect(url_for('dashboard'))

    @app.get('/')
    @require()
    def dashboard():
        return render_template('dashboard.html', metrics=metrics(), page='dashboard',
                               incidents=db().execute('SELECT * FROM incidents ORDER BY id DESC LIMIT 8').fetchall(),
                               audit=db().execute('SELECT * FROM audit ORDER BY id DESC LIMIT 8').fetchall())

    @app.get('/incidents')
    @require()
    def incidents():
        clauses, values = [], []
        query = request.args.get('q', '').strip()[:200]
        if query:
            clauses.append('(title LIKE ? OR details LIKE ? OR source LIKE ?)')
            values.extend(['%' + query + '%'] * 3)
        for column, allowed in [('severity', SEVERITIES), ('status', STATUSES)]:
            value = request.args.get(column, '').strip().capitalize()
            if value in allowed:
                clauses.append(column + '=?')
                values.append(value)
        sql = 'SELECT * FROM incidents' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
        return render_template('incidents.html', page='incidents',
                               incidents=db().execute(sql + ' ORDER BY id DESC LIMIT 500', values).fetchall())

    @app.post('/incidents/new')
    @require('admin', 'analyst')
    def new_incident():
        title = request.form.get('title', '').strip()
        severity = request.form.get('severity', 'Medium').strip().capitalize()
        source = request.form.get('source', 'Manual').strip() or 'Manual'
        details = request.form.get('details', '').strip()
        if not 1 <= len(title) <= 160 or severity not in SEVERITIES or len(source) > 100 or len(details) > 5000:
            abort(400, description='Check title (1–160), source (up to 100), details (up to 5000) and severity.')
        blob = title + ' ' + details
        iocs = extract_iocs(blob)
        playbook = suggest_playbook(blob) or ''
        priority = priority_for(severity, iocs)
        cursor = db().execute(
            'INSERT INTO incidents(title,severity,source,status,details,created_at,playbook,priority,updated_at)'
            ' VALUES(?,?,?,?,?,?,?,?,?)',
            (title, severity, source, 'Open', details, now(), playbook, priority, now()))
        incident_id = cursor.lastrowid
        for ioc in iocs:
            verdict, context = enrich(ioc['kind'], ioc['value'])
            db().execute('INSERT INTO observables(incident_id,kind,value,verdict,context,created_at,actor)'
                         ' VALUES(?,?,?,?,?,?,?)',
                         (incident_id, ioc['kind'], ioc['value'], verdict, context, now(), g.user['username']))
        audit('incident_created', f'Incident #{incident_id}: {title}')
        db().commit()
        note = f'Incident created. Auto-triage found {len(iocs)} indicator(s).'
        if playbook:
            note += f" Suggested playbook: {PLAYBOOKS[playbook]['name']}."
        flash(note, 'success')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.post('/incidents/<int:incident_id>/status')
    @require('admin', 'analyst')
    def update_status(incident_id):
        status = request.form.get('status', '').strip().capitalize()
        if status not in STATUSES:
            abort(400, description='Invalid incident status.')
        row = db().execute('SELECT status FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if not row:
            abort(404)
        db().execute('UPDATE incidents SET status=?, updated_at=? WHERE id=?', (status, now(), incident_id))
        audit('status_changed', f'Incident #{incident_id}: {row["status"]} → {status}')
        db().commit()
        flash('Incident status updated.', 'success')
        return redirect(safe_next(request.form.get('next'), url_for('incidents')))

    def load_incident(incident_id):
        row = db().execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if not row:
            abort(404)
        return row

    @app.get('/incidents/<int:incident_id>')
    @require()
    def incident_detail(incident_id):
        incident = load_incident(incident_id)
        observables = db().execute('SELECT * FROM observables WHERE incident_id=? ORDER BY id',
                                   (incident_id,)).fetchall()
        notes = db().execute('SELECT * FROM notes WHERE incident_id=? ORDER BY id DESC',
                             (incident_id,)).fetchall()
        approvals = db().execute('SELECT * FROM approvals WHERE incident_id=? ORDER BY id DESC',
                                 (incident_id,)).fetchall()
        analysts = db().execute("SELECT username FROM users WHERE active=1 AND role IN ('admin','analyst')"
                                ' ORDER BY username').fetchall()
        playbook = PLAYBOOKS.get(incident['playbook'])
        return render_template('incident.html', page='incidents', incident=incident,
                               observables=observables, notes=notes, approvals=approvals,
                               analysts=analysts, playbook=playbook, playbooks=PLAYBOOKS)

    @app.post('/incidents/<int:incident_id>/observables')
    @require('admin', 'analyst')
    def add_observable(incident_id):
        load_incident(incident_id)
        kind = request.form.get('kind', 'Other').strip()
        value = request.form.get('value', '').strip()
        if kind not in OBSERVABLE_KINDS or not 1 <= len(value) <= 500:
            abort(400, description='Provide a valid indicator type and value (1–500 characters).')
        verdict, context = enrich(kind, value)
        db().execute('INSERT INTO observables(incident_id,kind,value,verdict,context,created_at,actor)'
                     ' VALUES(?,?,?,?,?,?,?)',
                     (incident_id, kind, value, verdict, context, now(), g.user['username']))
        audit('observable_added', f'Incident #{incident_id}: {kind} {value} → {verdict}')
        db().commit()
        flash(f'Indicator enriched as {verdict} (simulated).', 'success')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.post('/incidents/<int:incident_id>/notes')
    @require('admin', 'analyst')
    def add_note(incident_id):
        load_incident(incident_id)
        body = request.form.get('body', '').strip()
        if not 1 <= len(body) <= 5000:
            abort(400, description='Notes must contain 1–5000 characters.')
        db().execute('INSERT INTO notes(incident_id,author,body,created_at) VALUES(?,?,?,?)',
                     (incident_id, g.user['username'], body, now()))
        audit('note_added', f'Incident #{incident_id}')
        db().commit()
        flash('Investigation note added.', 'success')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.post('/incidents/<int:incident_id>/assign')
    @require('admin', 'analyst')
    def assign_incident(incident_id):
        load_incident(incident_id)
        assignee = request.form.get('assignee', '').strip()[:80]
        if assignee:
            valid = db().execute("SELECT 1 FROM users WHERE username=? AND active=1 AND role IN ('admin','analyst')",
                                 (assignee,)).fetchone()
            if not valid:
                abort(400, description='Assignee must be an active analyst or administrator.')
        db().execute('UPDATE incidents SET assignee=?, updated_at=? WHERE id=?', (assignee, now(), incident_id))
        audit('incident_assigned', f'Incident #{incident_id} → {assignee or "unassigned"}')
        db().commit()
        flash('Assignment updated.', 'success')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.post('/incidents/<int:incident_id>/approvals')
    @require('admin', 'analyst')
    def request_approval(incident_id):
        load_incident(incident_id)
        action = request.form.get('action', '').strip()
        if not 1 <= len(action) <= 200:
            abort(400, description='Describe the requested response action (1–200 characters).')
        db().execute('INSERT INTO approvals(incident_id,action,requested_by,status,created_at) VALUES(?,?,?,?,?)',
                     (incident_id, action, g.user['username'], 'Pending', now()))
        audit('approval_requested', f'Incident #{incident_id}: {action}')
        db().commit()
        flash('Response action requested. Awaiting human approval — nothing was executed.', 'success')
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.get('/approvals')
    @require()
    def approvals():
        rows = db().execute('SELECT a.*, i.title AS incident_title FROM approvals a'
                            ' JOIN incidents i ON i.id=a.incident_id'
                            ' ORDER BY CASE a.status WHEN "Pending" THEN 0 ELSE 1 END, a.id DESC LIMIT 300').fetchall()
        return render_template('approvals.html', page='approvals', approvals=rows)

    @app.post('/approvals/<int:approval_id>/decide')
    @require('admin')
    def decide_approval(approval_id):
        row = db().execute('SELECT * FROM approvals WHERE id=?', (approval_id,)).fetchone()
        if not row:
            abort(404)
        if row['status'] != 'Pending':
            abort(400, description='This request has already been decided.')
        decision = request.form.get('decision', '').strip().capitalize()
        if decision not in ('Approved', 'Rejected'):
            abort(400, description='Decision must be Approved or Rejected.')
        db().execute('UPDATE approvals SET status=?, decided_by=?, decided_at=? WHERE id=?',
                     (decision, g.user['username'], now(), approval_id))
        audit('approval_decided', f'Incident #{row["incident_id"]}: {decision} ({row["action"]})')
        db().commit()
        flash(f'Request {decision.lower()} by human decision. No automated action ran.', 'success')
        return redirect(safe_next(request.form.get('next'), url_for('approvals')))

    @app.post('/api/ingest')
    def ingest():
        token = request.headers.get('X-Ingest-Token', '')
        if not token or not hmac.compare_digest(app.config['INGEST_TOKEN'], token):
            abort(401, description='A valid ingest token is required.')
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            abort(400, description='A JSON alert payload is required.')
        title = str(payload.get('title', '')).strip()[:160]
        severity = str(payload.get('severity', 'Medium')).strip().capitalize()
        source = str(payload.get('source', 'Webhook')).strip()[:100] or 'Webhook'
        details = str(payload.get('details', '')).strip()[:5000]
        if not 1 <= len(title) <= 160 or severity not in SEVERITIES:
            abort(400, description='Provide a title (1–160) and a valid severity.')
        blob = title + ' ' + details
        iocs = extract_iocs(blob)
        playbook = suggest_playbook(blob) or ''
        priority = priority_for(severity, iocs)
        cursor = db().execute(
            'INSERT INTO incidents(title,severity,source,status,details,created_at,playbook,priority,updated_at)'
            ' VALUES(?,?,?,?,?,?,?,?,?)',
            (title, severity, source, 'Open', details, now(), playbook, priority, now()))
        incident_id = cursor.lastrowid
        for ioc in iocs:
            verdict, context = enrich(ioc['kind'], ioc['value'])
            db().execute('INSERT INTO observables(incident_id,kind,value,verdict,context,created_at,actor)'
                         ' VALUES(?,?,?,?,?,?,?)',
                         (incident_id, ioc['kind'], ioc['value'], verdict, context, now(), 'webhook'))
        audit('alert_ingested', f'Incident #{incident_id}: {title} ({len(iocs)} indicators)', 'webhook')
        db().commit()
        return jsonify(status='created', incident_id=incident_id, indicators=len(iocs),
                       suggested_playbook=playbook or None, priority=priority, mode='simulated'), 201

    @app.get('/playbooks')
    @require()
    def playbooks():
        return render_template('playbooks.html', page='playbooks', playbooks=PLAYBOOKS)

    @app.post('/playbooks/<slug>/preview')
    @require()
    def preview_playbook(slug):
        if slug not in PLAYBOOKS:
            abort(404)
        audit('playbook_preview', slug + ' (no actions executed)')
        db().commit()
        return jsonify(name=PLAYBOOKS[slug]['name'], steps=PLAYBOOKS[slug]['steps'], mode='dry-run')

    @app.get('/integrations')
    @require()
    def integrations():
        return render_template('integrations.html', page='integrations',
                               ingest_token=app.config['INGEST_TOKEN'])

    @app.get('/reports')
    @require()
    def reports():
        counts = db().execute('SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity').fetchall()
        return render_template('reports.html', page='reports', metrics=metrics(), severities=counts)

    def insert_user(username, password, role, email='', must_change_password=False):
        username = username.strip().lower()
        if not 3 <= len(username) <= 80 or not all(c.isascii() and (c.isalnum() or c in '._-') for c in username):
            raise ValueError('Username must be 3–80 ASCII letters, digits, dots, underscores or hyphens.')
        if not 12 <= len(password) <= 128:
            raise ValueError('Use a password or passphrase between 12 and 128 characters.')
        if role not in ('admin', 'analyst', 'viewer'):
            raise ValueError('Invalid role.')
        if email and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[A-Za-z]{2,}', email):
            raise ValueError('Enter a valid email address.')
        db().execute('INSERT INTO users(username,password_hash,role,email,must_change_password) VALUES(?,?,?,?,?)',
                     (username, generate_password_hash(password), role, email,
                      1 if must_change_password else 0))
        return username

    @app.get('/admin')
    @require('admin')
    def admin():
        return render_template('admin.html', page='admin',
                               users=db().execute('SELECT id,username,role,active FROM users ORDER BY id').fetchall(),
                               audit=db().execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100').fetchall())

    @app.post('/admin/users')
    @require('admin')
    def create_user():
        try:
            username = insert_user(request.form.get('username', ''), request.form.get('password', ''),
                                   request.form.get('role', 'viewer'))
            audit('user_created', f'{username} ({request.form.get("role", "viewer")})')
            db().commit()
            flash('User created.', 'success')
        except (ValueError, sqlite3.IntegrityError) as error:
            db().rollback()
            flash(str(error) if isinstance(error, ValueError) else 'Username already exists.', 'error')
        return redirect(url_for('admin'))

    @app.post('/api/assistant')
    @require()
    def assistant():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get('message'), str):
            abort(400, description='A message is required.')
        message = payload['message'].strip().lower()
        if not 1 <= len(message) <= 1000:
            abort(400, description='Message must contain 1–1000 characters.')
        if any(word in message for word in ('summary', 'overview', 'count')):
            data = metrics()
            reply = (f"There are {data['total']} incidents: {data['open']} open, "
                     f"{data['investigating']} investigating and {data['resolved']} resolved. "
                     f"{data['critical']} have Critical severity (including resolved incidents).")
        elif any(word in message for word in ('login', 'password', 'credential')):
            reply = ' '.join(PLAYBOOKS['login-abuse']['steps'])
        elif any(word in message for word in ('powershell', 'endpoint', 'malware')):
            reply = ' '.join(PLAYBOOKS['endpoint-triage']['steps'])
        elif any(word in message for word in ('network', 'traffic', 'dns')):
            reply = ' '.join(PLAYBOOKS['network-review']['steps'])
        else:
            reply = ('I am a local rule-based guide, not an AI analyst. Ask for an incident summary, '
                     'failed-login guidance, endpoint triage or network review. I cannot inspect logs, '
                     'determine whether an alert is malicious, or execute response actions.')
        return jsonify(reply=reply)

    @app.get('/api/health')
    def health():
        return jsonify(status='ok', app='SOAR Sentinel', mode='demo', integrations_live=False)

    for code in (400, 401, 403, 404, 405, 413, 429, 500):
        def handle_error(error):
            message = 'An internal error occurred.' if error.code == 500 else error.description
            if request.path.startswith('/api/') or request.accept_mimetypes.best == 'application/json':
                return jsonify(error=message), error.code
            return render_template('error.html', code=error.code, message=message), error.code
        app.register_error_handler(code, handle_error)

    @app.cli.command('create-admin')
    @click.option('--username', prompt=True)
    @click.password_option(confirmation_prompt=True)
    def create_admin(username, password):
        """Create an administrator with an interactively entered password."""
        try:
            username = insert_user(username, password, 'admin')
            db().execute('INSERT INTO audit(created_at,actor,action,details) VALUES(?,?,?,?)',
                         (now(), 'local-cli', 'admin_created', username))
            db().commit()
        except (ValueError, sqlite3.IntegrityError) as error:
            db().rollback()
            raise click.ClickException(str(error)) from error
        click.echo('Administrator created.')

    @app.cli.command('seed-demo')
    def seed_demo():
        """Add sample incidents only to an empty incident database."""
        if db().execute('SELECT COUNT(*) FROM incidents').fetchone()[0]:
            raise click.ClickException('Incidents already exist; demo seeding skipped.')
        for title, severity, source in [('Multiple failed logins', 'High', 'Windows Event Log'),
                                        ('Suspicious PowerShell activity', 'Critical', 'Endpoint Alert'),
                                        ('Unusual outbound traffic', 'Medium', 'Network Monitor')]:
            blob = title + ' Suspicious PowerShell from 203.0.113.9 to login-secure-alert.zip'
            iocs = extract_iocs(blob)
            playbook = suggest_playbook(title) or ''
            priority = priority_for(severity, iocs)
            cursor = db().execute(
                'INSERT INTO incidents(title,severity,source,status,details,created_at,playbook,priority,updated_at)'
                ' VALUES(?,?,?,?,?,?,?,?,?)',
                (title, severity, source, 'Open', 'Synthetic example — not a live alert.', now(), playbook, priority, now()))
            for ioc in iocs[:3]:
                verdict, context = enrich(ioc['kind'], ioc['value'])
                db().execute('INSERT INTO observables(incident_id,kind,value,verdict,context,created_at,actor)'
                             ' VALUES(?,?,?,?,?,?,?)',
                             (cursor.lastrowid, ioc['kind'], ioc['value'], verdict, context, now(), 'seed'))
            db().execute('INSERT INTO notes(incident_id,author,body,created_at) VALUES(?,?,?,?)',
                         (cursor.lastrowid, 'seed', 'Auto-seeded example record for demonstration only.', now()))
        db().execute('INSERT INTO approvals(incident_id,action,requested_by,status,created_at) VALUES(?,?,?,?,?)',
                     (1, 'Disable affected account pending review', 'analyst', 'Pending', now()))
        db().commit()
        click.echo('Demo incidents added.')

    return app


if __name__ == '__main__':
    app = create_app()
    preferred_port = int(os.environ.get('SOAR_PORT') or os.environ.get('PORT') or 5000)
    try:
        app.run(host='127.0.0.1', port=preferred_port, debug=False)
    except OSError:
        if preferred_port == 5000 and not (os.environ.get('SOAR_PORT') or os.environ.get('PORT')):
            fallback_port = find_available_port(5001, 5100)
            print(f'Port 5000 is already in use; retrying on port {fallback_port}.')
            app.run(host='127.0.0.1', port=fallback_port, debug=False)
        else:
            raise