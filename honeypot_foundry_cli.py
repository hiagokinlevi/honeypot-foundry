import argparse
import os
import sys

from cli.main import run
from collectors.runtime import set_runtime_metadata


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot")
    parser.add_argument(
        "--instance-id",
        default=os.getenv("HONEYPOT_INSTANCE_ID"),
        help="Stable honeypot instance identifier (env: HONEYPOT_INSTANCE_ID)",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    known_args, remaining = parser.parse_known_args()

    if known_args.instance_id:
        set_runtime_metadata(instance_id=known_args.instance_id)

    sys.argv = [sys.argv[0], *remaining]
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
