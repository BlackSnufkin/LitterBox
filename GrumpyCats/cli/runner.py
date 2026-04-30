"""CLI runner — parse args, dispatch, handle exceptions uniformly.

Lifted out of `grumpycat.py` so the orchestrator stays a few lines.
"""

import logging
import sys

from litterbox_client import LitterBoxAPIError, LitterBoxError

from .handlers import COMMAND_HANDLERS
from .parser import build_parser, setup_client


def run(argv=None) -> int:
    """Parse `argv`, dispatch to the right handler, return an exit code.

    Catches the client's structured exceptions and turns them into clean
    error messages + non-zero exit codes. Unexpected exceptions print
    their type/message at INFO; with `--debug`, the full stack trace.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if not args.command:
        parser.print_help()
        return 0

    handler = COMMAND_HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        with setup_client(args) as client:
            handler(client, args)
        return 0
    except LitterBoxAPIError as e:
        logging.error(f"API Error (Status {e.status_code}): {str(e)}")
        if args.debug and e.response:
            logging.debug(f"Response data: {e.response}")
        return 1
    except LitterBoxError as e:
        logging.error(f"Client Error: {str(e)}")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        logging.error(f"Unexpected Error: {str(e)}")
        if args.debug:
            logging.exception("Detailed error information:")
        return 1
