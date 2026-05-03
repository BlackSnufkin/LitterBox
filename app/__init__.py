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


import re

# Werkzeug's access-log message arrives as:
#   `127.0.0.1 - - [03/May/2026 06:52:21] "GET /api/... HTTP/1.1" 200 -`
# The IP is always 127.0.0.1 in dev, the bracketed timestamp duplicates
# our own HH:MM:SS prefix, and the HTTP version is constant. Pull out
# the bits that vary and ditch the rest.
_ACCESS_LOG_RE = re.compile(
    r'^\S+ - - \[[^\]]+\] "(\S+) (\S+) HTTP/[\d.]+" (\d+) (-|\d+)$'
)


class _WerkzeugAccessFilter(logging.Filter):
    """Rewrite werkzeug HTTP access lines into `METHOD path → status`."""

    def filter(self, record):
        match = _ACCESS_LOG_RE.match(record.getMessage())
        if match:
            method, path, status, _size = match.groups()
            record.msg = f'{method:<6} {path}  → {status}'
            record.args = ()
        return True


class _CompactFormatter(logging.Formatter):
    """Compact, aligned, color-aware log formatter.

    Output shape (debug mode):
        HH:MM:SS  DEBUG  manager           Running yara
        HH:MM:SS  INFO   edr.elastic       Polling Elastic for detection alerts on DESKTOP-X (...)
        HH:MM:SS  WARN   edr_health        EDR health poller tick failed
        HH:MM:SS  INFO   http              GET    /api/edr/agents/status  → 200

    Width-fixed columns (5-char level, 16-char name) so timestamps and
    messages line up across the whole stream regardless of which logger
    emitted the record. ANSI color codes are appended AFTER width-padding
    so they don't break alignment.

    The original LogRecord is left untouched (the previous formatter
    mutated `record.levelname` / `record.msg` in place, which breaks
    re-emission through a second handler or filter chain).
    """

    LEVEL_COLORS = {
        'DEBUG':    Fore.CYAN,
        'INFO':     Fore.GREEN,
        'WARNING':  Fore.YELLOW,
        'ERROR':    Fore.RED,
        'CRITICAL': Fore.MAGENTA + Style.BRIGHT,
    }
    # 5-char fixed width — keeps the column aligned without losing the
    # severity glance value. WARNING -> WARN, CRITICAL -> CRIT.
    LEVEL_TAGS = {
        'DEBUG':    'DEBUG',
        'INFO':     'INFO ',
        'WARNING':  'WARN ',
        'ERROR':    'ERROR',
        'CRITICAL': 'CRIT ',
    }
    def format(self, record):
        ts = self.formatTime(record, datefmt='%H:%M:%S')

        level_tag = self.LEVEL_TAGS.get(record.levelname, record.levelname[:5].ljust(5))
        level_color = self.LEVEL_COLORS.get(record.levelname, '')
        level_part = f'{level_color}{level_tag}{Style.RESET_ALL}'

        # Name is dim-styled so the visual boundary to the message is
        # already clear — no need to right-pad to a fixed width, which
        # used to produce a lot of trailing whitespace on short names
        # (`http`, `app`, `api`). Level alignment alone gives enough
        # vertical structure for scanning.
        name = self._compact_name(record.name)
        name_part = f'{Style.DIM}{name}{Style.RESET_ALL}'

        message = record.getMessage()
        line = f'{ts}  {level_part}  {name_part}  {message}'

        # Mirror stdlib behaviour for exceptions / stack info.
        if record.exc_info:
            line = f'{line}\n{self.formatException(record.exc_info)}'
        if record.stack_info:
            line = f'{line}\n{self.formatStack(record.stack_info)}'
        return line

    @staticmethod
    def _compact_name(name: str) -> str:
        """Trim verbose dotted module paths down to something readable
        in the 16-char column. Drops the universal `app.` prefix, the
        per-package `services.` / `blueprints.` / `analyzers.` prefixes,
        and the `_analyzer` / `_edr_analyzer` suffix from analyzer
        modules. Renames `werkzeug` → `http` since every line that
        logger emits is an HTTP request."""
        if name == 'werkzeug':
            return 'http'
        if name.startswith('app.'):
            name = name[len('app.'):]
        for prefix in ('services.', 'blueprints.', 'analyzers.'):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        # Strip the `_edr_analyzer` flavor first, then the bare `_analyzer`.
        for suffix in ('_edr_analyzer', '_analyzer'):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
        return name


def setup_logging(app):
    """Install a single root-level handler for the whole app.

    Configuring at the root means every module logger created via
    `logging.getLogger(__name__)` (analyzers, services, edr clients,
    blueprints) inherits the same format without per-module setup. Run
    only in the Werkzeug reloader's child process to avoid duplicate
    output when debug mode is on.
    """
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    debug = bool(app.config.get('DEBUG'))
    level = logging.DEBUG if debug else logging.INFO

    if debug:
        formatter = _CompactFormatter()
    else:
        # Production output: timestamped, no ANSI, simple.
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)

    root = logging.getLogger()
    for h in root.handlers[:]:
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)

    # Flask creates its own logger with a default handler; clear it so
    # we don't duplicate every line. Propagation up to root carries the
    # message through our formatter.
    app.logger.handlers.clear()
    app.logger.setLevel(level)
    app.logger.propagate = True

    # Quiet down high-volume third-party loggers. urllib3's connection
    # pool dumps multi-line tracebacks at DEBUG every retry attempt,
    # which drowns out the analyzer logs operators actually came for.
    for noisy, lvl in (
        ('urllib3', logging.WARNING),
        ('urllib3.connectionpool', logging.WARNING),
        ('requests', logging.WARNING),
        ('requests.packages.urllib3', logging.WARNING),
        # Werkzeug's per-request access log stays at INFO so it shows
        # in debug mode but doesn't double-log via the root handler.
        ('werkzeug', logging.INFO),
    ):
        logging.getLogger(noisy).setLevel(lvl)

    # Compact werkzeug access lines: drop the redundant IP / bracketed
    # timestamp that duplicates our own HH:MM:SS prefix.
    werkzeug_logger = logging.getLogger('werkzeug')
    if not any(isinstance(f, _WerkzeugAccessFilter) for f in werkzeug_logger.filters):
        werkzeug_logger.addFilter(_WerkzeugAccessFilter())

    app.logger.debug('Logging configured (debug mode)')
