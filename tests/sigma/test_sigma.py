"""Offline tests for experimental Sigma atomic EVTX generation."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from wazuhtestgen.internal.sigma import (
    SIGMA_MIN_LEVEL,
    SigmaConverter,
    correlate,
    map_attack_tags,
    run_zircolite,
)


def wazuh_event(record: int, *, computer: str = "SERVER01") -> str:
    return json.dumps(
        {
            "win": {
                "system": {
                    "computer": computer,
                    "channel": "Security",
                    "eventID": "4625",
                    "eventRecordID": str(record),
                }
            }
        }
    )


@pytest.fixture
def no_backend_check(monkeypatch):
    """Converter tests fake run_zircolite, so skip the provider preflight."""
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.check_backend",
        lambda ruleset, config: (ruleset, config),
    )


def zircolite_event(record: int, *, computer: str = "SERVER01") -> dict:
    return {
        "Computer": computer,
        "Channel": "Security",
        "EventID": 4625,
        "EventRecordID": record,
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
        [detection(1), second, detection(2)],
        Path("Security.evtx"),
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
        [wazuh_event(1)],
        [correlated, bad, duplicate, duplicate, wrong_file],
        Path("Security.evtx"),
    )
    assert len(matches) == 1
    assert counts == {"correlations": 1, "unresolved": 2, "duplicates": 1}


def test_ambiguous_record_join_is_excluded() -> None:
    matches, counts = correlate(
        [wazuh_event(1), wazuh_event(1)],
        [detection(1)],
        Path("Security.evtx"),
    )
    assert matches == []
    assert counts["unresolved"] == 1


def test_level_and_attack_id_mapping() -> None:
    assert SIGMA_MIN_LEVEL["high"] == 10
    assert SIGMA_MIN_LEVEL["critical"] == 13
    assert map_attack_tags(["attack.t1110.001", "attack.credential-access"]) == (
        "T1110.001",
    )


def test_generates_runnable_parametrized_atomic_templates(
    tmp_path, monkeypatch, no_backend_check
) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    (input_dir / "Security.evtx").write_bytes(b"fixture")

    class FakeEvtxConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1), wazuh_event(2)])

    correlation = {
        "result_type": "correlation",
        "title": "PW Guessing",
        "matches": [{"alert_id": "s1", "event_ids": ["0:1"]}],
    }
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda *_args, **_kwargs: [detection(1), detection(2, "medium"), correlation],
    )
    SigmaConverter(FakeEvtxConverter()).convert(str(input_dir), str(output_dir))
    code = (output_dir / "test_sigma_security.py").read_text(encoding="utf-8")
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


def test_no_atomic_results_generate_no_parametrized_tests(
    tmp_path, monkeypatch, no_backend_check
) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    (input_dir / "Security.evtx").write_bytes(b"fixture")

    class FakeEvtxConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda *_args, **_kwargs: [{"result_type": "correlation", "matches": []}],
    )
    SigmaConverter(FakeEvtxConverter()).convert(str(input_dir), str(output_dir))
    code = (output_dir / "test_sigma_security.py").read_text(encoding="utf-8")
    ast.parse(code)
    assert "def test_sigma_atomic" not in code
    assert "# Correlations deferred: 1" in code


def test_subprocess_runner_reads_zircolite_result_array(
    tmp_path,
    monkeypatch,
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
        pytest.skip("Sigma optional dependency requires Python 3.11+")
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.importlib.util.find_spec",
        lambda name: object() if name == "zircolite" else None,
    )
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.subprocess.run",
        fake_run,
    )
    ruleset = tmp_path / "rules.json"
    mapping = tmp_path / "config.yaml"
    ruleset.write_text("[]", encoding="utf-8")
    mapping.write_text("{}", encoding="utf-8")
    assert (
        len(
            run_zircolite(
                evtx,
                ruleset=str(ruleset),
                config=str(mapping),
                pipelines=("sysmon", "windows-logsources"),
            )
        )
        == 1
    )
    assert commands[0][:3] == [sys.executable, "-m", "zircolite"]
    assert "--events" in commands[0]
    assert "--ruleset" in commands[0]
    assert commands[0][commands[0].index("--ruleset") + 1] == str(ruleset)
    assert commands[0][commands[0].index("--config") + 1] == str(mapping)
    assert commands[0].count("--pipeline") == 2
    assert commands[0][-4:] == [
        "--pipeline",
        "sysmon",
        "--pipeline",
        "windows-logsources",
    ]


def test_missing_optional_dependency_is_actionable(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.importlib.util.find_spec",
        lambda name: None,
    )
    with pytest.raises(
        RuntimeError, match=r"Python >=3.11|requirements/sigma-backend.txt"
    ):
        run_zircolite(tmp_path / "no.evtx")


def test_missing_zircolite_assets_fail_instead_of_silent_zero_matches(
    monkeypatch,
    tmp_path,
) -> None:
    if sys.version_info < (3, 11):
        pytest.skip("Optional Sigma mode requires Python 3.11+")

    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.importlib.util.find_spec",
        lambda _: object(),
    )
    with pytest.raises(RuntimeError, match="requires --ruleset and --mapping-config"):
        run_zircolite(tmp_path / "Security.evtx")
    with pytest.raises(FileNotFoundError, match="ruleset not found"):
        run_zircolite(
            tmp_path / "Security.evtx",
            ruleset=str(tmp_path / "missing.json"),
            config=str(tmp_path / "missing.yaml"),
        )


def test_sigma_is_public_cli_category() -> None:
    from wazuhtestgen.generator import _build_parser

    parser = _build_parser()
    args = parser.parse_args(
        [
            "sigma",
            "--input_dir",
            "input",
            "--output_dir",
            "output",
            "--ruleset",
            "rules.json",
            "--mapping-config",
            "config.yaml",
        ]
    )
    assert args.command == "sigma"
    assert args.ruleset == "rules.json"
    assert args.mapping_config == "config.yaml"
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "zircolite",
                "--input_dir",
                "input",
                "--output_dir",
                "output",
            ]
        )


def test_experimental_sigma_package_policy() -> None:
    root = Path(__file__).resolve().parents[2]
    overrides = (
        (root / "requirements" / "sigma-overrides.txt")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    active = {
        line.strip() for line in overrides if line.strip() and not line.startswith("#")
    }
    assert "pysigma>=2.0.0,<3" in active

    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert "sigma = [" in project
    # A direct Git URL in package metadata prevents publication to PyPI.
    assert "Zircolite @ git+" not in project
    backend = (root / "requirements" / "sigma-backend.txt").read_text(encoding="utf-8")
    assert "Zircolite @ git+https://github.com/wagga40/Zircolite.git@" in backend
    assert "wazuhtester>=0.1,<1; platform_system == 'Linux'" in project


def test_zircolite_non_utf8_failure_output_remains_reportable(
    tmp_path, monkeypatch
) -> None:
    """A Windows console may emit invalid cp1252/UTF-8 byte sequences."""
    if sys.version_info < (3, 11):
        pytest.skip("Sigma optional dependency requires Python 3.11+")
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.importlib.util.find_spec",
        lambda _: object(),
    )
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.subprocess.run",
        lambda *_args, **kwargs: SimpleNamespace(
            returncode=1,
            stderr=b"\x90 unexpected console output",
            stdout=b"",
        ),
    )
    ruleset = tmp_path / "probe.json"
    config = tmp_path / "config.yaml"
    ruleset.write_text("[]", encoding="utf-8")
    config.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Zircolite failed:") as raised:
        run_zircolite(
            tmp_path / "sample.evtx",
            ruleset=str(ruleset),
            config=str(config),
        )
    assert "unexpected console output" in str(raised.value)


def test_unjoinable_atomic_matches_are_not_a_successful_generation(
    tmp_path,
    monkeypatch,
    no_backend_check,
) -> None:
    inp = tmp_path / "input"
    out = tmp_path / "output"
    inp.mkdir()
    (inp / "Security.evtx").write_bytes(b"fixture")

    class FakeConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda *_args, **_kwargs: [detection(999)],
    )
    with pytest.raises(RuntimeError, match="none joined uniquely"):
        SigmaConverter(FakeConverter()).convert(str(inp), str(out))
    assert list(out.glob("test_sigma_*.py")) == []


def test_native_sigma_pipeline_argument_is_repeatable() -> None:
    from wazuhtestgen.generator import _build_parser

    args = _build_parser().parse_args(
        [
            "sigma",
            "-i",
            "input",
            "-o",
            "output",
            "--ruleset",
            "sigma.yaml",
            "--mapping-config",
            "config.yaml",
            "--pipeline",
            "sysmon",
            "--pipeline",
            "windows-logsources",
        ]
    )
    assert args.pipeline == ["sysmon", "windows-logsources"]


def test_failure_in_any_file_writes_no_partial_output(
    tmp_path,
    monkeypatch,
    no_backend_check,
) -> None:
    inp = tmp_path / "input"
    out = tmp_path / "output"
    inp.mkdir()
    (inp / "a.evtx").write_bytes(b"fixture")
    (inp / "b.evtx").write_bytes(b"fixture")

    class FakeConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda evtx, *_args, **_kwargs: [
            detection(1 if evtx.name == "a.evtx" else 999)
        ],
    )
    with pytest.raises(RuntimeError, match="No test files were written"):
        SigmaConverter(FakeConverter()).convert(str(inp), str(out))
    assert not out.exists() or list(out.iterdir()) == []


def test_existing_output_is_rejected_before_backend_runs(
    tmp_path,
    monkeypatch,
    no_backend_check,
) -> None:
    inp = tmp_path / "input"
    out = tmp_path / "output"
    inp.mkdir()
    out.mkdir()
    (inp / "Security.evtx").write_bytes(b"fixture")
    (out / "test_sigma_security.py").write_text("# keep\n", encoding="utf-8")

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("backend ran before the overwrite check")

    monkeypatch.setattr("wazuhtestgen.internal.sigma.run_zircolite", must_not_run)

    class FakeConverter:
        def to_json(self, _path):
            raise AssertionError("EVTX parsed before the overwrite check")

    with pytest.raises(FileExistsError, match="--force"):
        SigmaConverter(FakeConverter()).convert(str(inp), str(out))
    assert (out / "test_sigma_security.py").read_text(encoding="utf-8") == "# keep\n"


def test_force_replaces_existing_output(
    tmp_path,
    monkeypatch,
    no_backend_check,
) -> None:
    inp = tmp_path / "input"
    out = tmp_path / "output"
    inp.mkdir()
    out.mkdir()
    (inp / "Security.evtx").write_bytes(b"fixture")
    (out / "test_sigma_security.py").write_text("# stale\n", encoding="utf-8")

    class FakeConverter:
        def to_json(self, _path):
            return iter([wazuh_event(1)])

    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda *_args, **_kwargs: [detection(1)],
    )
    SigmaConverter(FakeConverter(), overwrite=True).convert(str(inp), str(out))
    code = (out / "test_sigma_security.py").read_text(encoding="utf-8")
    assert "pytest.param(" in code


@pytest.mark.parametrize(
    "names",
    [("a/b.evtx", "a_b.evtx"), ("Security.evtx", "security.EVTX")],
)
def test_output_name_collision_is_reported_as_collision(
    tmp_path,
    names,
    no_backend_check,
) -> None:
    inp = tmp_path / "input"
    for name in names:
        path = inp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")
    if len(list(inp.rglob("*.*"))) < 2:
        pytest.skip("case-insensitive filesystem")

    class FakeConverter:
        def to_json(self, _path):
            raise AssertionError("EVTX parsed before the collision check")

    with pytest.raises(ValueError, match="name collision"):
        SigmaConverter(FakeConverter()).convert(str(inp), str(tmp_path / "out"))


def test_rules_without_id_are_not_merged_as_duplicates() -> None:
    first = detection(1)
    second = detection(1)
    first["id"] = ""
    del second["id"]
    second["title"] = "Another rule"
    matches, counts = correlate(
        [wazuh_event(1)], [first, second], Path("Security.evtx")
    )
    assert len(matches) == 2
    assert counts["duplicates"] == 0


def test_force_is_a_sigma_cli_option() -> None:
    from wazuhtestgen.generator import _build_parser

    base = [
        "sigma",
        "-i",
        "input",
        "-o",
        "output",
        "--ruleset",
        "rules.json",
        "--mapping-config",
        "config.yaml",
    ]
    assert _build_parser().parse_args(base).force is False
    assert _build_parser().parse_args([*base, "--force"]).force is True


def test_cli_failure_creates_no_output_directory(
    tmp_path,
    monkeypatch,
    no_backend_check,
) -> None:
    from wazuhtestgen import generator

    inp = tmp_path / "input"
    out = tmp_path / "output"
    inp.mkdir()
    (inp / "Security.evtx").write_bytes(b"fixture")

    class FakeEvtxConverter:
        converter = SimpleNamespace(to_json=lambda _path: iter([wazuh_event(1)]))

    monkeypatch.setattr(generator, "EvtxConverter", FakeEvtxConverter)
    monkeypatch.setattr(
        "wazuhtestgen.internal.sigma.run_zircolite",
        lambda *_args, **_kwargs: [detection(999)],
    )
    args = generator._build_parser().parse_args(
        [
            "sigma",
            "-i",
            str(inp),
            "-o",
            str(out),
            "--ruleset",
            "rules.json",
            "--mapping-config",
            "config.yaml",
        ]
    )
    with pytest.raises(RuntimeError, match="none joined uniquely"):
        generator.main(args)
    assert not out.exists()
