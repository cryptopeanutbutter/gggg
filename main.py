"""Entry point for WHOIS Watching."""
from __future__ import annotations

import argparse
import os
import sys

from PyQt5 import QtWidgets

from gui import MainWindow


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WHOIS Watching defensive console")
    parser.add_argument("--lab-mode", action="store_true", help="Enable Lab Mode modules (requires passphrase)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.lab_mode:
        os.environ["WHOIS_WATCHING_LAB"] = "1"
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
