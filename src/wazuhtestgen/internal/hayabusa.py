"""Experimental Hayabusa-assisted test generation, independent of live logtest."""
from __future__ import annotations

import json
import logging
import pathlib
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from typing import Any, Iterable

from .naming import identifier
from .attack_mapping import map_attack_id

TECHNIQUE = re.compile(r"^(?:attack[.:])?(t\d{4}(?:\.\d{3})?)$", re.I)
# These are advisory, editable review levels, NOT an official Sigma-Wazuh mapping.
DEFAULT_LEVELS = {
    "informational": 3, "info": 3,
    "low": 5,
    "medium": 7, "med": 7,
    "high": 10,
    "critical": 13, "crit": 13,
}


def map_attack_tags(value: Any) -> tuple[str, ...]:
    """Keep technique/subtechnique IDs; do not invent IDs from tactics."""
    if value is None:
        return ()
    if isinstance(value, str):
        tags = re.split(r"[,;\s|¦]+", value.strip("[]"))
    elif isinstance(value, (list, tuple, set)):
        tags = value
    else:
        return ()
    ids = set()
    for tag in tags:
        match = TECHNIQUE.fullmatch(str(tag).strip().strip("'\""))
        if match:
            ids.add(map_attack_id(match.group(1).upper()))
    return tuple(sorted(ids))


def event_identity(data: dict[str, Any]) -> tuple[str, str, str, str] | None:
    sys = data.get("win", {}).get("system", {})
    if not isinstance(sys, dict):
        return None
    fields = [sys.get(x) for x in ("computer", "channel", "eventRecordID", "eventID")]
    if any(x is None or str(x).strip() == "" for x in fields):
        return None
    return (str(fields[0]).casefold(), str(fields[1]).casefold(),
            str(fields[2]), str(fields[3]))


def finding_identity(item: dict[str, Any]) -> tuple[str, str, str, str] | None:
    values = [item.get(x) for x in ("Computer", "Channel", "RecordID", "EventID")]
    if any(x is None or str(x).strip() == "" for x in values):
        return None
    return (str(values[0]).casefold(), str(values[1]).casefold(),
            str(values[2]), str(values[3]))


def is_replayable_finding(item: dict[str, Any]) -> bool:
    """Only an event with a numeric RecordID can be replayed atomically.

    Hayabusa aggregation/correlation rows use RecordID '-' instead of an
    individual Windows event record. Missing IDs are also not replayable.
    """
    value = item.get("RecordID")
    return not isinstance(value, bool) and str(value).isdecimal()


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8-sig") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def run_hayabusa(evtx_path: pathlib.Path, executable: str = "hayabusa") -> list[dict[str, Any]]:
    resolved = shutil.which(executable)
    if not resolved:
        raise RuntimeError("Hayabusa executable not found in PATH: " + executable)
    with tempfile.TemporaryDirectory(prefix="wazuhtestgen-hayabusa-") as tmp:
        output = pathlib.Path(tmp) / "timeline.jsonl"
        command = [resolved, "dfir-timeline", "--file", str(evtx_path),
                   "--output-type", "jsonl", "--profile", "verbose",
                   "--output", str(output), "--no-wizard", "--quiet",
                   "--disable-abbreviations"]
        result = subprocess.run(command, capture_output=True, text=True,
                                check=False, timeout=900)
        if result.returncode:
            raise RuntimeError("Hayabusa failed: " + (result.stderr or result.stdout)[-1500:])
        if not output.is_file():
            raise RuntimeError("Hayabusa produced no timeline")
        return read_jsonl(output)


def correlate(logs: Iterable[str], findings: Iterable[dict[str, Any]]
              ) -> tuple[list[tuple[int, dict[str, Any]]], int]:
    """Only exact, unique joins; rejects ambiguity and incomplete identities."""
    index: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    for i, log in enumerate(logs):
        key = event_identity(json.loads(log))
        if key:
            index[key].append(i)
    matched = []
    unresolved = 0
    for item in findings:
        key = finding_identity(item)
        candidates = index.get(key, []) if key else []
        if len(candidates) != 1:
            unresolved += 1
        else:
            matched.append((candidates[0], item))
    return matched, unresolved


class HayabusaConverter:
    """Generate per-detection, reviewable Wazuh pytest assertions from EVTX."""
    def __init__(self, evtx_converter: Any, executable: str = "hayabusa") -> None:
        self.evtx_converter = evtx_converter
        self.executable = executable

    def convert(self, input_directory: str, output_directory: str) -> None:
        source = pathlib.Path(input_directory)
        target = pathlib.Path(output_directory)
        target.mkdir(parents=True, exist_ok=True)
        for evtx in sorted(source.rglob("*")):
            if not evtx.is_file() or evtx.suffix.lower() != ".evtx":
                continue
            logs = list(self.evtx_converter.to_json(evtx))
            findings = run_hayabusa(evtx, self.executable)
            event_findings = [item for item in findings if is_replayable_finding(item)]
            skipped_non_event = len(findings) - len(event_findings)
            matched, unresolved = correlate(logs, event_findings)
            if skipped_non_event or unresolved:
                logging.warning(
                    "Hayabusa %s: %d non-event/correlation rows skipped, "
                    "%d event rows could not be uniquely matched",
                    evtx, skipped_non_event, unresolved,
                )
            # One parametrized test per EVTX file. Each Hayabusa finding remains
            # an independently reported pytest case, even for shared records.
            cases: list[str] = []
            for number, (index, hit) in enumerate(matched):
                rule_uuid = str(hit.get("RuleID", "")).strip()
                if not rule_uuid:
                    raise ValueError(f"{evtx}: Hayabusa result missing RuleID")
                severity = str(hit.get("Level", "")).lower()
                level = DEFAULT_LEVELS.get(severity)
                tags = map_attack_tags(hit.get("MitreTags"))
                title = str(hit.get("RuleTitle", "Detection"))
                record_id = str(hit.get("RecordID", "unknown"))
                case_id = identifier(
                    f"record_{record_id}_sigma_{rule_uuid}_{number}",
                    fallback="case",
                )
                cases.append(
                    f"    # Sigma: {rule_uuid.encode('unicode_escape').decode('ascii')}; title: {title.encode('unicode_escape').decode('ascii')}\n"
                    f"    pytest.param(\n"
                    f"        {logs[index]!r},\n"
                    f"        {level!r},\n"
                    f"        {tags!r},\n"
                    f"        id={case_id!r},\n"
                    f"    ),\n"
                )

            test_code = ""
            if cases:
                test_code = (
                    "@pytest.mark.parametrize(\n"
                    "    ('log', 'expected_level', 'expected_mitre_ids'),\n"
                    "    [\n" + "".join(cases) + "    ],\n"
                    ")\n"
                    "def test_hayabusa_detection(log, expected_level, expected_mitre_ids) -> None:\n"
                    "    # Proposed expectations: edit to fit your installed Wazuh ruleset.\n"
                    "    # Optional: assert response.rule_id == '<your_rule_id>'\n"
                    "    assert expected_level is not None, 'Set minimum level using your ruleset policy'\n"
                    "    response = send_log(log, log_format='json')\n"
                    "    assert response.status is LogtestStatus.RuleMatch\n"
                    "    assert response.alert\n"
                    "    assert response.rule_level is not None\n"
                    "    assert response.rule_level >= expected_level\n"
                    "    assert expected_mitre_ids, 'Set expected ATT&CK technique IDs for this case'\n"
                    "    assert set(expected_mitre_ids) <= response.rule_mitre_ids\n\n"
                )
            else:
                test_code = "# No correlated Hayabusa detections; no test cases generated.\n"
            name = identifier(str(evtx.relative_to(source).with_suffix("")).replace("\\", "_").replace("/", "_"))
            destination = target / f"test_hayabusa_{name}.py"
            if destination.exists():
                raise ValueError(f"Refusing to overwrite existing test module: {destination}")
            destination.write_text(
                "# Best-effort TDD drafts: initial assertion failures are expected (Red).\n"
                "# Review expected levels, MITRE IDs, and optional rule ID before Green.\n"
                "import pytest\nfrom wazuhtester import LogtestStatus, send_log\n"
                "pytestmark = pytest.mark.wazuh_logtest\n\n"
                + f"# Hayabusa non-event/correlation findings skipped: {skipped_non_event}\n"
                + f"# Unmatched/ambiguous atomic findings skipped: {unresolved}\n\n"
                + test_code,
                encoding="utf-8",
            )
