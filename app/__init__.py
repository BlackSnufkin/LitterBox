import logging
import os
from types import SimpleNamespace

import yaml
from colorama import Fore, Style, init
from flask import Flask, render_template, request

# Initialize colorama for Windows compatibility
init(autoreset=True)


def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)


def create_app():
    app = Flask(__name__)

    # Load configuration from YAML
    config = load_config()
    app.config.update(config)
    app.name = config['application']['name']

    # Create all necessary directories
    paths_to_create = {
        config['utils']['upload_folder'],
        config['utils']['result_folder'],
        config['analysis']['doppelganger']['db']['path'],
        os.path.join(
            config['analysis']['doppelganger']['db']['path'],
            config['analysis']['doppelganger']['db']['blender'],
        ),
        os.path.join(
            config['analysis']['doppelganger']['db']['path'],
            config['analysis']['doppelganger']['db']['fuzzyhash'],
        ),
    }
    for path in paths_to_create:
        os.makedirs(path, exist_ok=True)

    # Wire shared dependencies once; blueprints read them via current_app.extensions
    from .analyzers.manager import AnalysisManager
    from .analyzers.edr import registry as edr_registry
    from .helpers import RouteHelpers

    # Load EDR profiles from Config/edr_profiles/*.yml so the upload page can
    # render one button per profile and the dispatcher knows which profiles
    # are valid. Missing/invalid profiles are logged and skipped — they don't
    # prevent the rest of LitterBox from starting.
    edr_registry.init(app.config)

    app.extensions['litterbox'] = SimpleNamespace(
        manager=AnalysisManager(app.config, logger=app.logger),
        helpers=RouteHelpers(app.config, app.logger),
        edr_registry=edr_registry,
        config=app.config,
    )

    # Pre-warm the EDR-agent reachability cache so the dashboard never
    # waits for a fresh probe cycle. Idempotent — safe across reloads.
    from .services.edr_health import start_poller
    start_poller(app.extensions['litterbox'])

    # Register blueprints
    from .blueprints import (
        analysis_bp,
        api_bp,
        doppelganger_bp,
        management_bp,
        results_bp,
        upload_bp,
    )

    app.register_blueprint(upload_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(doppelganger_bp)
    app.register_blueprint(management_bp)
    app.register_blueprint(api_bp)

    @app.errorhandler(404)
    def page_not_found(error):
        app.logger.debug(f"Page not found: {request.path}")
        return render_template('error.html', error=f"Page not found: {request.path}"), 404

    return app


def setup_logging(app):
    """Configure logging with selective colors and avoid duplicate logs."""
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    if app.config['DEBUG']:
        log_level = logging.DEBUG

        from flask.logging import default_handler
        app.logger.setLevel(log_level)

        class ColoredFormatter(logging.Formatter):
            LOG_COLORS = {
                "DEBUG": Fore.CYAN,
                "INFO": Fore.GREEN,
                "WARNING": Fore.YELLOW,
                "ERROR": Fore.RED,
                "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
            }

            def format(self, record):
                log_color = self.LOG_COLORS.get(record.levelname, "")
                levelname_color = f"{log_color}{record.levelname}{Style.RESET_ALL}"
                message = f"{Style.RESET_ALL}{record.msg}"
                record.levelname = levelname_color
                record.msg = message
                return super().format(record)

        formatter = ColoredFormatter('[%(asctime)s - %(name)s] [%(levelname)s] - %(message)s')
        default_handler.setFormatter(formatter)

        app.logger.debug("Debug logging is enabled.")
