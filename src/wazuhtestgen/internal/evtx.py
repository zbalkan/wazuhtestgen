from __future__ import annotations

import logging
import os
import pathlib
import platform

from .naming import claim_unique_name, identifier

logger = logging.getLogger(__name__)


class EvtxConverter:
    def __init__(self) -> None:
        if platform.system() != "Windows":
            raise RuntimeError("EVTX parsing works only on Windows platforms.")

        try:
            from wazuhevtx.evtx2json import EvtxToJson
        except ImportError as exc:
            raise RuntimeError(
                "The EVTX command requires the wazuhevtx package."
            ) from exc

        self.converter = EvtxToJson()

    def convert(self, input_directory: str, output_directory: str) -> None:
        """Convert EVTX files to editable pytest templates."""

        output_names: dict[str, str] = {}

        for root, _, files in os.walk(input_directory):
            evtx_files = [name for name in files if name.endswith(".evtx")]
            if not evtx_files:
                continue

            subdirs = pathlib.Path(root).relative_to(input_directory).parts
            directory_source = str(pathlib.Path(*subdirs)) if subdirs else "."
            directory_name = claim_unique_name(
                identifier("_".join(subdirs), fallback="root"),
                directory_source,
                output_names,
                kind="EVTX output module",
            )
            logger.info(
                "Generating EVTX pytest module for directory: %s",
                directory_name,
            )

            test_functions: list[str] = []
            function_names: dict[str, str] = {}

            for filename in evtx_files:
                file_path = pathlib.Path(root, filename)
                rel_path = str(file_path.relative_to(input_directory))
                logger.info("Processing EVTX file: %s", rel_path)

                function_name = claim_unique_name(
                    identifier(
                        rel_path.removesuffix(".evtx"),
                        fallback="evtx",
                    ),
                    rel_path,
                    function_names,
                    kind="EVTX test function",
                )

                json_logs = list(self.converter.to_json(file_path))
                formatted_logs = "\n".join(f"        {log!r}," for log in json_logs)

                test_functions.append(
                    f"""\
@pytest.mark.skip(reason={"Define expected detections for " + rel_path!r})
def test_{function_name}() -> None:
    logs: list[str] = [
{formatted_logs}
    ]

    responses = send_multiple_logs(logs, log_format="json")

    assert len(responses) == len(logs)

    # TODO: Add scenario-specific assertions for rule IDs, levels,
    # groups, MITRE ATT&CK techniques, or other expected outcomes.


"""
                )

            test_code = """\
import pytest
from wazuhtester import send_multiple_logs

pytestmark = pytest.mark.wazuh_logtest


""" + "".join(test_functions)

            test_file_path = os.path.join(
                output_directory,
                f"test_{directory_name}.py",
            )

            os.makedirs(output_directory, exist_ok=True)
            with open(test_file_path, "w", encoding="utf-8") as test_file:
                test_file.write(test_code)

            print(f"Test file '{test_file_path}' generated successfully.")
