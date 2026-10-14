"""One-off helper: create the first admin + demo data for local preview.
Run:  python _seed_admin.py      (local demo only)"""
import sqlite3

import app as app_module
from werkzeug.security import generate_password_hash

application = app_module.create_app()

# Ensure the schema + instance exist
with application.app_context():
    pass

path = application.config['DATABASE']
con = sqlite3.connect(path)
con.row_factory = sqlite3.Row
try:
    try:
        con.execute('INSERT INTO users(username,password_hash,role,active) VALUES(?,?,?,1)',
                    ('admin', generate_password_hash('Admin12345!demo'), 'admin'))
        con.commit()
        print('Created admin  ->  username: admin   password: Admin12345!demo')
    except sqlite3.IntegrityError:
        print('Admin already exists.')

    count = con.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
    if count == 0:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        rows = [
            ('Multiple failed logins', 'High', 'Windows Event Log', 'Investigating',
             'Credential abuse suspected; review auth events.', now, '', 'login-abuse', 2, now),
            ('Suspicious PowerShell activity from 203.0.113.9 to login-secure-alert.zip',
             'Critical', 'Endpoint Alert', 'Open',
             'Obfuscated command contacted a suspicious zip domain.', now, '', 'endpoint-triage', 1, now),
            ('Unusual outbound traffic', 'Medium', 'Network Monitor', 'Open',
             'High-volume upload to unfamiliar destination.', now, '', 'network-review', 3, now),
        ]
        for r in rows:
            cur = con.execute('INSERT INTO incidents(title,severity,source,status,details,created_at,'
                              'assignee,playbook,priority,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)', r)
            iid = cur.lastrowid
            for kind, value in [('IPv4', '203.0.113.9'), ('Domain', 'login-secure-alert.zip')]:
                con.execute('INSERT INTO observables(incident_id,kind,value,verdict,context,created_at,actor)'
                            ' VALUES(?,?,?,?,?,?,?)',
                            (iid, kind, value, 'Malicious', 'Matches the local simulated blocklist.', now, 'seed'))
        con.execute('INSERT INTO approvals(incident_id,action,requested_by,status,created_at) VALUES(?,?,?,?,?)',
                    (2, 'Disable affected account pending review', 'admin', 'Pending', now))
        con.execute('INSERT INTO notes(incident_id,author,body,created_at) VALUES(?,?,?,?)',
                    (2, 'seed', 'Auto-seeded example record for demonstration only.', now))
        con.commit()
        print('Seeded 3 demo incidents with indicators, a note, and a pending approval.')
    else:
        print('Incidents already exist; skipping demo seed.')
finally:
    con.close()