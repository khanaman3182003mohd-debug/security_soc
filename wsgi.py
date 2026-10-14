"""WSGI entry point for production (Render / gunicorn).
Exposes `application` so gunicorn can serve the app:

    gunicorn wsgi:application --bind 0.0.0.0:$PORT --workers 2 --threads 4
"""
from app import create_app

# The WSGI callable that Render / gunicorn looks for.
application = create_app()
