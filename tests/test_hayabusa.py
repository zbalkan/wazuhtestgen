from __future__ import annotations

import ast
import json

from wazuhtestgen.internal.hayabusa import (
    HayabusaConverter, correlate, map_attack_tags, read_jsonl,
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
    assert "@pytest.mark.skip(" in generated
    assert "expected_level = 10" in generated
    assert "T1110.001" in generated
    assert "response.rule_mitre_ids" in generated
    assert "response.rule_id ==" not in generated


def test_jsonl_reader(tmp_path) -> None:
    path = tmp_path / "timeline.jsonl"
    path.write_text(json.dumps(finding(1)) + "\n", encoding="utf-8")
    assert read_jsonl(path)[0]["RecordID"] == 1
