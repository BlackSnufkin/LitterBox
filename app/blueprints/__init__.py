# app/blueprints/__init__.py
from .analysis import analysis_bp
from .api import api_bp
from .doppelganger import doppelganger_bp
from .management import management_bp
from .results import results_bp
from .upload import upload_bp

__all__ = [
    'analysis_bp', 'api_bp', 'doppelganger_bp',
    'management_bp', 'results_bp', 'upload_bp',
]
