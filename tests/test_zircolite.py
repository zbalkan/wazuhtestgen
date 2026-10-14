"""Offline tests for Zircolite's structured atomic detection adapter."""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from wazuhtestgen.internal.zircolite import (
    SIGMA_MIN_LEVEL, ZircoliteConverter, correlate, map_attack_tags, run_zircolite,
)


def wazuh_event(record: int, *, computer: str = "SERVER01") -> str:
    return json.dumps({"win": {"system": {
        "computer": computer, "channel": "Security",
        "eventID": "4625", "eventRecordID": str(record),
    }}})


def zircolite_event(record: int, *, computer: str = "SERVER01") -> dict:
    return {
        "Computer": computer, "Channel": "Security",
        "EventID": 4625, "EventRecordID": record,
        "OriginalLogfile": "Security.evtx",
    }


def detection(record: int, level: str = "high") -> dict:
    return {
        "title": "Failed Logon - Incorrect Password",
        "id": "5b0b75dc-9190-4047-b9a8-14164cee8a31",
        "rule_level": level,
        "tags": ["attack.credential_access", "attack.t1110.001"],
        "matches": [zircolite_event(record)],
    }


def test_atomic_correlation_preserves_events_and_rules() -> None:
    second = detection(1)
    second["id"] = "2fad5c03-ce0b-4e19-8d2d-b9d36e310dad"
    second["tags"] = ["attack.t1059.001"]
    matches, counts = correlate(
        [wazuh_event(1), wazuh_event(2)],
        [detection(1), second, detection(2)], Path("Security.evtx"),
    )
    assert [idx for idx, _ in matches] == [0, 0, 1]
    assert counts == {"correlations": 0, "unresolved": 0, "duplicates": 0}


def test_correlation_alerts_are_ignored_and_unresolved_does_not_abort() -> None:
    correlated = {
        "result_type": "correlation",
        "title": "PW Guessing",
        "matches": [{"group_keys": {"IpAddress": "10.1.1.1"}, "event_ids": ["0:1"]}],
    }
    bad = detection(100)
    duplicate = detection(1)
    wrong_file = detection(1)
    wrong_file["matches"][0]["OriginalLogfile"] = "elsewhere.evtx"

    matches, counts = correlate(
        [wazuh_event(1)], [correlated, bad, duplicate, duplicate, wrong_file],
        Path("Security.evtx"),
    )
    assert len(matches) == 1
    assert counts == {"correlations": 1, "unresolved": 2, "duplicates": 1}


def test_ambiguous_record_join_is_excluded() -> None:
    matches, counts = correlate(
        [wazuh_event(1), wazuh_event(1)],
        [detection(1)], Path("Security.evtx"),
    )
    assert matches == []
    assert counts["unresolved"] == 1


def test_level_and_attack_id_mapping() -> None:
    assert SIGMA_MIN_LEVEL["high"] == 10
    assert SIGMA_MIN_LEVEL["critical"] == 13
    assert map_attack_tags(["attack.t1110.001", "attack.credential-access"]) == (
        "T1110.001",
    )


def test_generates_runnable_parametrized_atomic_templates(tmp_path, monkeypatch) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    (input_dir / "Security.evtx").write_bytes(b"fixture")

    class FakeEvtxConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1), wazuh_event(2)])

    correlation = {
        "result_type": "correlation", "title": "PW Guessing",
        "matches": [{"alert_id": "s1", "event_ids": ["0:1"]}],
    }
    monkeypatch.setattr(
        "wazuhtestgen.internal.zircolite.run_zircolite",
        lambda *_args: [detection(1), detection(2, "medium"), correlation],
    )
    ZircoliteConverter(FakeEvtxConverter()).convert(str(input_dir), str(output_dir))
    code = (output_dir / "test_zircolite_security.py").read_text(encoding="utf-8")
    tree = ast.parse(code)
    assert len([x for x in tree.body if isinstance(x, ast.FunctionDef)]) == 1
    assert code.count("pytest.param(") == 2
    assert "@pytest.mark.skip" not in code
    assert "assert response.alert" in code
    assert "response.rule_level >= expected_level" in code
    assert "set(expected_mitre_ids) <= response.rule_mitre_ids" in code
    assert "# Correlations deferred: 1" in code
    assert "        10," in code
    assert "        7," in code
    assert "T1110.001" in code
    assert "assert response.rule_id ==" not in code


def test_no_atomic_results_generate_no_parametrized_tests(tmp_path, monkeypatch) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    (input_dir / "Security.evtx").write_bytes(b"fixture")

    class FakeEvtxConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.zircolite.run_zircolite",
        lambda *_args: [{"result_type": "correlation", "matches": []}],
    )
    ZircoliteConverter(FakeEvtxConverter()).convert(str(input_dir), str(output_dir))
    code = (output_dir / "test_zircolite_security.py").read_text(encoding="utf-8")
    ast.parse(code)
    assert "def test_zircolite_atomic" not in code
    assert "# Correlations deferred: 1" in code


def test_subprocess_runner_reads_zircolite_result_array(
    tmp_path, monkeypatch,
) -> None:
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"fixture")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        out = Path(command[command.index("--outfile") + 1])
        out.write_text(json.dumps([detection(1)]), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    if sys.version_info < (3, 11):
        pytest.skip("Zircolite optional dependency requires Python 3.11+")
    monkeypatch.setattr(
        "wazuhtestgen.internal.zircolite.importlib.util.find_spec",
        lambda name: object() if name == "zircolite" else None,
    )
    monkeypatch.setattr(
        "wazuhtestgen.internal.zircolite.subprocess.run", fake_run,
    )
    assert len(run_zircolite(evtx, ruleset="rules.json")) == 1
    assert commands[0][:3] == [sys.executable, "-m", "zircolite"]
    assert "--events" in commands[0]
    assert "--ruleset" in commands[0]
    assert commands[0][-1] == "rules.json"


def test_missing_optional_dependency_is_actionable(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "wazuhtestgen.internal.zircolite.importlib.util.find_spec",
        lambda name: None,
    )
    with pytest.raises(RuntimeError, match=r"Python >=3.11|wazuhtestgen\\[zircolite\\]"):
        run_zircolite(tmp_path / "no.evtx")
