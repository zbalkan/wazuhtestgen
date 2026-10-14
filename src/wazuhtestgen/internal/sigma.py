"""Sigma-assisted atomic EVTX pytest drafts (Zircolite backend).

The optional Zircolite >=4.5 package requires Python >=3.11. Run its module
entry point in a separate process to isolate Zircolite's application-level
state and avoid depending on private internal APIs.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from typing import Any, Iterable

from .attack_mapping import map_attack_id
from .naming import identifier

TECHNIQUE = re.compile(r"^(?:attack[.:])?(t\d{4}(?:\.\d{3})?)$", re.I)
# Proposed minimum Wazuh alert levels, not official Sigma equivalences.
SIGMA_MIN_LEVEL = {
    "informational": 3, "info": 3,
    "low": 5,
    "medium": 7, "med": 7,
    "high": 10,
    "critical": 13, "crit": 13,
}


def map_attack_tags(value: Any) -> tuple[str, ...]:
    """Normalize Sigma ATT&CK technique IDs, then apply explicit exceptions."""
    if isinstance(value, str):
        items = re.split(r"[,;\s|¦]+", value.strip("[]"))
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        return ()
    ids = set()
    for item in items:
        match = TECHNIQUE.fullmatch(str(item).strip().strip("'\""))
        if match:
            ids.add(map_attack_id(match.group(1).upper()))
    return tuple(sorted(ids))


def event_identity(value: dict[str, Any]) -> tuple[str, str, str, str] | None:
    system = value.get("win", {}).get("system", {})
    if not isinstance(system, dict):
        return None
    fields = tuple(system.get(field) for field in
                   ("computer", "channel", "eventRecordID", "eventID"))
    if any(field is None or str(field).strip() == "" for field in fields):
        return None
    return (str(fields[0]).casefold(), str(fields[1]).casefold(),
            str(fields[2]), str(fields[3]))


def matched_event_identity(event: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """Identity of a *flattened* Zircolite event (not a correlation alert)."""
    fields = tuple(event.get(field) for field in
                   ("Computer", "Channel", "EventRecordID", "EventID"))
    if any(field is None or str(field).strip() == "" for field in fields):
        return None
    return (str(fields[0]).casefold(), str(fields[1]).casefold(),
            str(fields[2]), str(fields[3]))


def run_zircolite(evtx: pathlib.Path,
                  ruleset: str | None = None,
                  config: str | None = None) -> list[dict[str, Any]]:
    if sys.version_info < (3, 11):
        raise RuntimeError(
            "The experimental Sigma mode requires Python >=3.11. "
            "Install wazuhtestgen[sigma] in a Python 3.11+ environment."
        )
    if importlib.util.find_spec("zircolite") is None:
        raise RuntimeError(
            "The optional Zircolite package is not installed. "
            "Install wazuhtestgen[sigma] with Python >=3.11."
        )
    if not ruleset or not config:
        raise RuntimeError(
            "The experimental Sigma mode requires --ruleset and "
            "--mapping-config. Install the Zircolite source assets separately "
            "and supply their actual file paths."
        )
    if not pathlib.Path(ruleset).exists():
        raise FileNotFoundError("Zircolite ruleset not found: " + ruleset)
    if not pathlib.Path(config).is_file():
        raise FileNotFoundError("Zircolite field-mapping config not found: " + config)
    with tempfile.TemporaryDirectory(prefix="wazuhtestgen-zircolite-") as temp:
        output = pathlib.Path(temp) / "detections.json"
        command = [
            sys.executable, "-m", "zircolite", "--events", str(evtx),
            "--outfile", str(output), "--quiet", "--no-parallel",
            "--ruleset", str(pathlib.Path(ruleset).resolve()),
            "--config", str(pathlib.Path(config).resolve()),
        ]
        # Capture raw bytes. Zircolite's Windows console output can contain
        # bytes that are invalid in the runner's locale (for example cp1252).
        # text=True creates reader threads which can crash while decoding and
        # conceal the actual subprocess error or output.
        result = subprocess.run(
            command, capture_output=True,
            check=False, timeout=900,
        )
        if result.returncode != 0:
            diagnostics = (result.stderr or result.stdout).decode(
                "utf-8", errors="replace"
            )
            raise RuntimeError("Zircolite failed: " + diagnostics[-1500:])
        if not output.is_file():
            raise RuntimeError("Zircolite did not create its detection JSON")
        data = json.loads(output.read_text(encoding="utf-8-sig"))
        if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
            raise RuntimeError("Unexpected Zircolite result: expected a JSON array")
        return data


def correlate(
    logs: Iterable[str],
    results: Iterable[dict[str, Any]],
    evtx_file: pathlib.Path,
) -> tuple[list[tuple[int, dict[str, Any]]], dict[str, int]]:
    """Associate atomic detections with unique Wazuh event records.

    Returns (record index, parent Zircolite rule). Correlation alerts are
    intentionally ignored. Never use timestamps or fuzzy event matching.
    """
    index: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    for position, log in enumerate(logs):
        identity = event_identity(json.loads(log))
        if identity:
            index[identity].append(position)

    matched: list[tuple[int, dict[str, Any]]] = []
    counts = {"correlations": 0, "unresolved": 0, "duplicates": 0}
    seen: set[tuple[int, str]] = set()
    for result in results:
        if result.get("result_type") == "correlation":
            counts["correlations"] += 1
            continue
        for event in result.get("matches", ()):
            if not isinstance(event, dict):
                counts["unresolved"] += 1
                continue
            source = event.get("OriginalLogfile")
            if source:
                original = pathlib.PureWindowsPath(str(source)).name
                if original.casefold() != evtx_file.name.casefold():
                    counts["unresolved"] += 1
                    continue
            identity = matched_event_identity(event)
            positions = index.get(identity, ()) if identity else ()
            if len(positions) != 1:
                counts["unresolved"] += 1
                continue
            position = positions[0]
            key = (position, str(result.get("id", "")))
            if key in seen:
                counts["duplicates"] += 1
                continue
            seen.add(key)
            matched.append((position, result))
    return matched, counts


class SigmaConverter:
    """Generate runnable best-effort, atomic pytest cases from EVTX and Sigma."""

    def __init__(self, evtx_converter: Any,
                 ruleset: str | None = None,
                 config: str | None = None) -> None:
        self.evtx_converter = evtx_converter
        self.ruleset = ruleset
        self.config = config

    def convert(self, input_directory: str, output_directory: str) -> None:
        source = pathlib.Path(input_directory)
        destination = pathlib.Path(output_directory)
        destination.mkdir(parents=True, exist_ok=True)

        for evtx in sorted(source.rglob("*")):
            if not evtx.is_file() or evtx.suffix.lower() != ".evtx":
                continue
            logs = list(self.evtx_converter.to_json(evtx))
            detections = run_zircolite(evtx, self.ruleset, self.config)
            matches, counts = correlate(logs, detections, evtx)
            if any(counts.values()):
                logging.warning("%s: skipped/ignored Sigma backend results: %s",
                                evtx, counts)

            parameters: list[str] = []
            for ordinal, (position, detection) in enumerate(matches):
                source_id = str(detection.get("id", "")).strip()
                title = str(detection.get("title", "Untitled Sigma detection"))
                level = SIGMA_MIN_LEVEL.get(
                    str(detection.get("rule_level", "")).strip().lower()
                )
                mitre = map_attack_tags(detection.get("tags"))
                identity = event_identity(json.loads(logs[position]))
                record_id = identity[2] if identity else "unknown"
                case_id = identifier(
                    f"record_{record_id}_sigma_{source_id or title}_{ordinal}",
                    fallback="case",
                )
                parameters.append(
                    f"    # Sigma: {source_id.encode('unicode_escape').decode('ascii')}; "
                    f"title: {title.encode('unicode_escape').decode('ascii')}\n"
                    "    pytest.param(\n"
                    f"        {logs[position]!r},\n"
                    f"        {level!r},\n"
                    f"        {mitre!r},\n"
                    f"        id={case_id!r},\n"
                    "    ),\n"
                )

            if parameters:
                function = (
                    "@pytest.mark.parametrize(\n"
                    "    ('log', 'expected_level', 'expected_mitre_ids'),\n"
                    "    [\n" + "".join(parameters) + "    ],\n"
                    ")\n"
                    "def test_sigma_atomic(log, expected_level, expected_mitre_ids):\n"
                    "    # Best-effort proposed expectations; edit for your ruleset.\n"
                    "    assert expected_level is not None, 'Set a minimum Wazuh alert level'\n"
                    "    assert expected_mitre_ids, 'Set an expected ATT&CK technique ID'\n"
                    "    response = send_log(log, log_format='json')\n"
                    "    assert response.status is LogtestStatus.RuleMatch\n"
                    "    assert response.alert\n"
                    "    assert response.rule_level is not None\n"
                    "    assert response.rule_level >= expected_level\n"
                    "    assert set(expected_mitre_ids) <= response.rule_mitre_ids\n"
                )
            else:
                function = "# No uniquely correlated atomic detections.\n"

            out_name = identifier(
                str(evtx.relative_to(source).with_suffix(""))
                .replace("\\", "_").replace("/", "_")
            )
            output = destination / f"test_sigma_{out_name}.py"
            if output.exists():
                raise ValueError("Refusing to overwrite existing test: " + str(output))
            output.write_text(
                "# Best-effort TDD templates: assertion failures are expected in Red.\n"
                "import pytest\n"
                "from wazuhtester import LogtestStatus, send_log\n\n"
                "pytestmark = pytest.mark.wazuh_logtest\n\n"
                f"# Correlations deferred: {counts['correlations']}\n"
                f"# Atomic events unresolved: {counts['unresolved']}\n"
                f"# Duplicate matches ignored: {counts['duplicates']}\n\n"
                + function, encoding="utf-8",
            )
