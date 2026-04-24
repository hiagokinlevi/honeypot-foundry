#!/usr/bin/env python3
"""Compatibility entrypoint for honeypot CLI."""

from cli.main import main


if __name__ == "__main__":
    raise SystemExit(main())
