#!/usr/bin/env python3

from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
from typing import Final

from .internal.evtx import EvtxConverter
from .internal.zircolite import ZircoliteConverter
from .internal.ini import IniConverter
from .internal.rule import RuleConverter

APP_NAME: Final[str] = "wazuhtestgen"
APP_VERSION: Final[str] = "0.4.1"
DESCRIPTION: Final[str] = (
    f"{APP_NAME} ({APP_VERSION}) generates pytest-formatted Wazuh rule tests "
    "from Wazuh INI regression tests, Windows EVTX files, or Wazuh rule XML."
)
ENCODING: Final[str] = "utf-8"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, help_text in (
        ("ini", "Generate pytest tests from Wazuh INI regression tests."),
        ("evtx", "Generate editable pytest templates from EVTX files."),
        ("zircolite", "Generate Zircolite-informed atomic EVTX pytest drafts (experimental)."),
        ("rule", "Generate editable pytest templates from Wazuh rule XML files."),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument(
            "--input_dir", "-i", required=True,
            help="Directory where input files are located.",
        )
        subparser.add_argument(
            "--output_dir", "-o", required=True,
            help="Directory where generated Python tests will be saved.",
        )
        if command == "zircolite":
            subparser.add_argument(
                "--ruleset", default=None,
                help="Optional explicit Zircolite JSON ruleset or Sigma YAML path.",
            )
    return parser


def _parse_args() -> argparse.Namespace:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command in ("evtx", "zircolite") and platform.system() != "Windows":
        parser.error(
            f"the {args.command} command requires Windows, because wazuhevtx reads EVTX "
            "files through the Windows event log API. The ini and rule commands "
            "run on any operating system."
        )
    return args


def main(args: argparse.Namespace | None = None) -> None:
    """Run the command-line generator."""
    if args is None:
        args = _parse_args()

    logging.info("Starting %s %s", APP_NAME, APP_VERSION)
    logging.info(DESCRIPTION)

    input_directory = args.input_dir
    output_directory = args.output_dir

    if not os.path.exists(input_directory):
        print(f"Error: Input directory '{input_directory}' not found.")
        raise SystemExit(1)

    os.makedirs(output_directory, exist_ok=True)

    if args.command == "ini":
        ini_converter = IniConverter()
        wazuh_test_inis = [
            filename
            for filename in os.listdir(input_directory)
            if filename.endswith(".ini")
        ]
        if not wazuh_test_inis:
            raise FileNotFoundError(f"No INI files found in {input_directory}")

        for wazuh_test_ini in wazuh_test_inis:
            logging.info("Processing INI file: %s", wazuh_test_ini)
            ini_converter.convert(
                os.path.join(input_directory, wazuh_test_ini),
                output_directory,
            )
    elif args.command == "evtx":
        EvtxConverter().convert(input_directory, output_directory)
    elif args.command == "zircolite":
        ZircoliteConverter(
            EvtxConverter().converter,
            ruleset=args.ruleset,
        ).convert(input_directory, output_directory)
    elif args.command == "rule":
        RuleConverter().convert(input_directory, output_directory)


def run() -> int:
    """Run the installed console command with user-facing error handling."""
    try:
        args = _parse_args()
        setup_logging(debug=args.debug)
        main(args)
    except KeyboardInterrupt:
        print("Cancelled by user.")
        logging.info("Cancelled by user.")
        return 130
    except SystemExit as ex:
        return ex.code if isinstance(ex.code, int) else 1
    except RuntimeError as ex:
        print("ERROR: " + str(ex), file=sys.stderr)
        exception_handler(type(ex), ex, ex.__traceback__)
        return 2
    except Exception as ex:
        print("ERROR: " + str(ex), file=sys.stderr)
        exception_handler(type(ex), ex, ex.__traceback__)
        return 1
    return 0


def exception_handler(exc_type, exc_value, exc_traceback) -> None:
    if logging.root.level == logging.DEBUG:
        logging.error(
            "Unhandled exception",
            exc_info=(exc_type, exc_value, exc_traceback),
        )
    else:
        logging.error("(%s): %s", exc_type.__name__, exc_value)


def get_log_path() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, APP_NAME, "Logs", f"{APP_NAME}.log")

    if sys.platform == "darwin":
        return os.path.join(
            os.path.expanduser("~"),
            "Library", "Logs", APP_NAME, f"{APP_NAME}.log",
        )

    base = os.environ.get("XDG_STATE_HOME")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, APP_NAME, f"{APP_NAME}.log")


def setup_logging(*, debug: bool = False) -> None:
    log_path = get_log_path()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        filename=log_path,
        encoding=ENCODING,
        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.DEBUG if debug else logging.INFO,
    )
    sys.excepthook = exception_handler


if __name__ == "__main__":
    raise SystemExit(run())
