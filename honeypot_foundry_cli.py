"""Repository-unique console entrypoint wrapper."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def _load_cli():
    cli_path = Path(__file__).resolve().parent / "cli" / "main.py"
    spec = spec_from_file_location("honeypot_foundry_runtime_cli", cli_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load CLI module from {cli_path}")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.cli


cli = _load_cli()


if __name__ == "__main__":
    cli()
