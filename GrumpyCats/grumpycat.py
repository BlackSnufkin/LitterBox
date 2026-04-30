"""GrumpyCats — CLI orchestrator for the LitterBox payload-analysis sandbox.

The CLI surface and the API client are split into packages:

  litterbox_client/   — the LitterBoxClient class, composed from
                        per-domain mixins (files / analysis / doppelganger /
                        results / edr / reports / system).

  cli/                — argparse parser, per-command handlers, and the
                        runner that ties them together.

This module stays a few lines on purpose — it just dispatches into
`cli.run`. Adding a new command means: write a method in the right
client mixin, add a subparser in `cli/parser.py`, write a `_cmd_*`
handler in `cli/handlers.py`, register it in `COMMAND_HANDLERS`. Done.
"""

import sys

from cli import run


def main():
    sys.exit(run())


if __name__ == "__main__":
    main()
