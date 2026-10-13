from __future__ import annotations

import ast
import json

from wazuhtestgen.internal.attack_mapping import ATTACK_ID_OVERRIDES, map_attack_id
from wazuhtestgen.internal.hayabusa import (
    HayabusaConverter, correlate, is_replayable_finding,
    map_attack_tags, read_jsonl, run_hayabusa,
)


def log(record: int, computer: str = "host") -> str:
    return json.dumps({"win": {"system": {
        "computer": computer, "channel": "Security",
        "eventID": "4625", "eventRecordID": str(record),
    }}})


def finding(record: int, *, computer: str = "host") -> dict:
    return {
        "Computer": computer, "Channel": "Security",
        "EventID": 4625, "RecordID": record,
        "RuleID": "5b0b75dc-9190-4047-b9a8-14164cee8a31",
        "RuleTitle": "Wrong password",
        "Level": "high", "MitreTags": ["attack.t1110.001", "attack.credential-access"],
    }


def test_attack_mapper_excludes_tactics_groups_and_software() -> None:
    assert map_attack_tags([
        "attack.t1110", "attack.t1110.001", "attack.ta0006",
        "attack.g0001", "attack.s0001", "attack.credential_access",
        "T1110.001", "bad",
    ]) == ("T1110", "T1110.001")


def test_exact_join_does_not_cross_record_and_computer() -> None:
    matches, missing = correlate([log(1), log(1, "other")], [
        finding(1), finding(1, computer="other"), finding(2),
    ])
    assert [index for index, _ in matches] == [0, 1]
    assert missing == 1


def test_ambiguous_identity_not_joined() -> None:
    matched, unresolved = correlate([log(1), log(1)], [finding(1)])
    assert matched == []
    assert unresolved == 1


def test_file_generation_uses_metadata_without_claiming_wazuh_rule_id(
    tmp_path, monkeypatch,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / "sample.evtx").write_bytes(b"fixture")
    class Converter:
        def to_json(self, _path):
            return iter([log(1)])
    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.run_hayabusa",
        lambda *_args: [finding(1)],
    )
    HayabusaConverter(Converter()).convert(str(source), str(output))
    generated = (output / "test_hayabusa_sample.py").read_text(encoding="utf-8")
    ast.parse(generated)
    assert "@pytest.mark.skip(" not in generated
    assert "Best-effort TDD drafts" in generated
    assert "assert response.status is LogtestStatus.RuleMatch" in generated
    assert "@pytest.mark.parametrize(" in generated
    assert generated.count("pytest.param(") == 1
    assert generated.count("def test_hayabusa_detection(") == 1
    assert "        10," in generated
    assert "T1110.001" in generated
    assert "response.rule_mitre_ids" in generated
    assert "assert response.alert" in generated
    assert "response.rule_level >= expected_level" in generated
    assert "assert response.rule_id ==" not in generated


def test_jsonl_reader(tmp_path) -> None:
    path = tmp_path / "timeline.jsonl"
    path.write_text(json.dumps(finding(1)) + "\n", encoding="utf-8")
    assert read_jsonl(path)[0]["RecordID"] == 1


def test_attack_mapper_defaults_to_identity() -> None:
    assert map_attack_id("t1110.001") == "T1110.001"
    assert map_attack_tags(["attack.t1110.001", "T1059"]) == ("T1059", "T1110.001")


def test_attack_mapper_only_uses_explicit_exception(monkeypatch) -> None:
    monkeypatch.setitem(ATTACK_ID_OVERRIDES, "T1234.001", "T1234")
    assert map_attack_tags(["attack.t1234.001", "attack.t8888.001"]) == (
        "T1234", "T8888.001"
    )


def test_multiple_findings_generate_independent_parametrized_cases(
    tmp_path, monkeypatch,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / "sample.evtx").write_bytes(b"fixture")

    class Converter:
        def to_json(self, _path):
            return iter([log(1), log(2)])

    first = finding(1)
    second = dict(finding(1))
    second["RuleID"] = "8ad49a15-0451-4f64-bd84-2db59f46d692"
    second["MitreTags"] = ["attack.t1059.001"]
    third = finding(2)
    third["Level"] = "medium"
    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.run_hayabusa",
        lambda *_args: [first, second, third],
    )

    HayabusaConverter(Converter()).convert(str(source), str(output))
    generated = (output / "test_hayabusa_sample.py").read_text(encoding="utf-8")
    tree = ast.parse(generated)

    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    assert len(functions) == 1
    assert functions[0].name == "test_hayabusa_detection"
    assert generated.count("pytest.param(") == 3
    assert generated.count("record_1_sigma_") == 2
    assert generated.count("record_2_sigma_") == 1
    assert "T1059.001" in generated
    assert "        7," in generated
    assert "response.rule_level >= expected_level" in generated


def test_no_correlations_does_not_generate_empty_parametrized_test(
    tmp_path, monkeypatch,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / "sample.evtx").write_bytes(b"fixture")

    class Converter:
        def to_json(self, _path):
            return iter([log(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.run_hayabusa",
        lambda *_args: [],
    )
    HayabusaConverter(Converter()).convert(str(source), str(output))
    generated = (output / "test_hayabusa_sample.py").read_text(encoding="utf-8")
    ast.parse(generated)
    assert "def test_hayabusa_detection(" not in generated
    assert "pytest.param(" not in generated
    assert "No correlated Hayabusa detections" in generated


def test_correlation_results_are_not_atomic_events() -> None:
    correlation = {
        "RecordID": "-", "RuleID": "23179f25-6fce-4827-bae1-b219deaf563e",
        "RuleTitle": "PW Guessing", "Details": {"Count": 5},
    }
    assert not is_replayable_finding(correlation)
    assert not is_replayable_finding({"RecordID": None})
    assert not is_replayable_finding({"RecordID": "invalid"})
    assert is_replayable_finding(finding(14021))


def test_correlations_and_unmatched_events_do_not_block_atomic_generation(
    tmp_path, monkeypatch,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()
    (source / "sample.evtx").write_bytes(b"fixture")

    class Converter:
        def to_json(self, _path):
            return iter([log(1), log(2), log(3)])

    first = finding(1)
    first["Level"] = "info"
    second = finding(2)
    second["Level"] = "med"
    third = finding(3)
    third["Level"] = "crit"
    correlation = {
        **finding(1),
        "RecordID": "-",
        "RuleID": "23179f25-6fce-4827-bae1-b219deaf563e",
        "RuleTitle": "PW Guessing",
    }
    unmatched = finding(999)
    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.run_hayabusa",
        lambda *_args: [correlation, unmatched, first, second, third],
    )
    HayabusaConverter(Converter()).convert(str(source), str(output))
    generated = (output / "test_hayabusa_sample.py").read_text(encoding="utf-8")
    ast.parse(generated)
    assert generated.count("pytest.param(") == 3
    assert "23179f25" not in generated
    assert "# Hayabusa non-event/correlation findings skipped: 1" in generated
    assert "# Unmatched/ambiguous atomic findings skipped: 1" in generated
    assert "        3," in generated
    assert "        7," in generated
    assert "        13," in generated
    assert "assert expected_mitre_ids" in generated


def test_hayabusa_cli_disables_abbreviations_for_exact_channel_join(
    tmp_path, monkeypatch,
) -> None:
    from types import SimpleNamespace

    evtx = tmp_path / "sample.evtx"
    evtx.write_bytes(b"fixture")
    executed = []

    def fake_run(command, **_kwargs):
        executed.extend(command)
        from pathlib import Path
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps(finding(1)) + "\\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.shutil.which",
        lambda command: "C:/tools/hayabusa.exe",
    )
    monkeypatch.setattr(
        "wazuhtestgen.internal.hayabusa.subprocess.run", fake_run,
    )
    records = run_hayabusa(evtx, "hayabusa")
    assert len(records) == 1
    assert "--disable-abbreviations" in executed
    assert executed[executed.index("--profile") + 1] == "verbose"
    assert executed[executed.index("--output-type") + 1] == "jsonl"


def test_attack_mapper_accepts_hayabusa_display_delimiters() -> None:
    assert map_attack_tags("T1110.001 ¦ attack.t1059.001") == (
        "T1059.001", "T1110.001"
    )
