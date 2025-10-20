"""Utility script for storing encrypted API keys."""
from __future__ import annotations

import argparse
import sys
from typing import Optional

# Ensure repository root is on sys.path when executed from scripts/ directory
if __name__ == "__main__" and __package__ is None:
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from utils import settings  # noqa: E402


def _ensure_cryptography_available() -> None:
    try:
        settings.load_settings()
    except RuntimeError as exc:
        message = str(exc)
        if "cryptography" in message.lower():
            raise SystemExit(
                "Error: cryptography is required. Install dependencies with "
                "'python -m pip install -r requirements.txt' or run scripts\\install.bat"
            ) from exc
        raise


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Securely store or remove API keys inside WHOIS Watching's encrypted "
            "settings bundle."
        )
    )
    parser.add_argument(
        "--service",
        default="openai",
        help="Name of the API service (default: openai).",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--key", help="API key value to store.")
    group.add_argument(
        "--clear",
        action="store_true",
        help="Remove the stored key for the service.",
    )
    parser.add_argument(
        "--model",
        help="Optional model identifier to store alongside the key.",
    )

    args = parser.parse_args(argv)

    _ensure_cryptography_available()

    config = settings.load_settings()

    if args.clear:
        removed = config.api_keys.pop(args.service, None)
        if args.model:
            config.api_keys.pop(f"{args.service}_model", None)
        settings.save_settings(config)
        if removed:
            print(f"Removed stored key for service '{args.service}'.")
        else:
            print(f"No stored key found for service '{args.service}'.")
        return 0

    config.api_keys[args.service] = args.key
    if args.model:
        config.api_keys[f"{args.service}_model"] = args.model

    settings.save_settings(config)
    print(
        "API key updated successfully. Launch WHOIS Watching to confirm the AI "
        "link indicator reflects the new configuration."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - manual utility
    raise SystemExit(main())
