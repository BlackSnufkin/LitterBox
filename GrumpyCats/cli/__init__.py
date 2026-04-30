"""CLI parser + per-command handlers.

The orchestrator (`grumpycat.py`) imports `build_parser`, `setup_client`,
`COMMAND_HANDLERS`, and `run` from here and stays minimal.
"""

from .handlers import COMMAND_HANDLERS
from .parser import build_parser, setup_client
from .runner import run

__all__ = ["build_parser", "setup_client", "COMMAND_HANDLERS", "run"]
