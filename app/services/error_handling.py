# app/services/error_handling.py
"""Shared error-handling decorator for blueprint routes."""
from functools import wraps

from flask import current_app, jsonify


def error_handler(f):
    """Wrap a route handler to log exceptions and return a JSON 500."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            current_app.logger.error(f"Error in {f.__name__}: {e}")
            current_app.logger.error("Traceback:", exc_info=True)
            return jsonify({'error': str(e)}), 500
    return decorated_function
