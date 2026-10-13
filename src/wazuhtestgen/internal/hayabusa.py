"""Experimental Hayabusa-assisted test generation, independent of live logtest."""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from typing import Any, Iterable

from .naming import identifier

TECHNIQUE = re.compile(r"^(?:attack[.:])?(t\d{4}(?:\.\d{3})?)$", re.I)
# These are advisory, editable review levels, NOT an official Sigma-Wazuh mapping.
DEFAULT_LEVELS = {"informational": 3, "low": 5, "medium": 7,
                  "high": 10, "critical": 12}


def map_attack_tags(value: Any) -> tuple[str, ...]:
    """Keep technique/subtechnique IDs; do not invent IDs from tactics."""
    if value is None:
        return ()
    if isinstance(value, str):
        tags = re.split(r"[,;\s]+", value.strip("[]"))
    elif isinstance(value, (list, tuple, set)):
        tags = value
    else:
        return ()
    ids = set()
    for tag in tags:
        match = TECHNIQUE.fullmatch(str(tag).strip().strip("'\""))
        if match:
            ids.add(match.group(1).upper())
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
                   "--output", str(output), "--no-wizard", "--quiet"]
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
            matched, unresolved = correlate(logs, findings)
            if unresolved:
                raise ValueError(f"{evtx}: {unresolved} Hayabusa findings cannot be uniquely correlated")
            cases: list[str] = []
            for number, (index, hit) in enumerate(matched):
                rule_uuid = str(hit.get("RuleID", "")).strip()
                if not rule_uuid:
                    raise ValueError(f"{evtx}: Hayabusa result missing RuleID")
                severity = str(hit.get("Level", "")).lower()
                level = DEFAULT_LEVELS.get(severity)
                tags = map_attack_tags(hit.get("MitreTags"))
                title = str(hit.get("RuleTitle", "Detection"))
                function = identifier(f"{evtx.stem}_{number}_{rule_uuid}", fallback="detection")
                # Hayabusa does not establish a Wazuh rule ID. Assert only reviewable metadata.
                cases.append(
                    f"def test_{function}() -> None:\n"
                    f"    # Sigma/Hayabusa: {rule_uuid}\n"
                    f"    # Title: {title.encode('unicode_escape').decode('ascii')}\n"
                    f"    # Source: {str(evtx.relative_to(source))!r}, record {hit.get('RecordID')!r}\n"
                    f"    log = {logs[index]!r}\n"
                    f"    response = send_log(log, log_format='json')\n"
                    f"    assert response.status is LogtestStatus.RuleMatch\n"
                    f"    assert response.alert\n"
                    f"    # Proposed expectations, based on Hayabusa metadata; edit to fit your ruleset.\n"
                    f"    expected_level = {level!r}\n"
                    f"    expected_mitre_ids = {tags!r}\n"
                    f"    # Optional: add assert response.rule_id == '<your_rule_id>'\n"
                    f"    assert expected_level is not None, 'Set expected_level using your ruleset policy'\n"
                    f"    assert response.rule_level is not None\n"
                    f"    assert response.rule_level >= expected_level\n"
                    f"    assert set(expected_mitre_ids) <= response.rule_mitre_ids\n\n"
                )
            name = identifier(str(evtx.relative_to(source).with_suffix("")).replace("\\", "_").replace("/", "_"))
            destination = target / f"test_hayabusa_{name}.py"
            if destination.exists():
                raise ValueError(f"Refusing to overwrite existing test module: {destination}")
            destination.write_text(
                "# Best-effort TDD drafts: initial assertion failures are expected (Red).\n"
                "# Review expected levels, MITRE IDs, and optional rule ID before Green.\n"
                "import pytest\nfrom wazuhtester import LogtestStatus, send_log\n"
                "pytestmark = pytest.mark.wazuh_logtest\n\n" + "".join(cases),
                encoding="utf-8",
            )
