#!/usr/bin/env bash
# Render start script — prepares the database, creates a first admin if needed, then serves.
set -e

# Use a database path inside the project (Render provides $PORT at runtime)
export SOAR_DB_PATH="${SOAR_DB_PATH:-$(pwd)/instance/soar.db}"
mkdir -p "$(dirname "$SOAR_DB_PATH")"

# Ensure the database + tables exist
python -c "import app; app.create_app()"

# Create a default admin ONLY if the database has no users yet (first run)
python -c "
import sqlite3
from werkzeug.security import generate_password_hash
import app as a
application = a.create_app()
con = sqlite3.connect(application.config['DATABASE'])
try:
    n = con.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if n == 0:
        con.execute('INSERT INTO users(username,password_hash,role,active) VALUES(?,?,?,1)',
                    ('admin', generate_password_hash('Admin12345!demo'), 'admin'))
        con.commit()
        print('Created default admin (admin / Admin12345!demo) - CHANGE THIS PASSWORD!')
    else:
        print('Users already exist; skipping admin creation.')
finally:
    con.close()
"

# Serve with gunicorn (production WSGI server)
exec gunicorn --bind 0.0.0.0:"${PORT:-5000}" --workers 2 --threads 4 "app:create_app()"

