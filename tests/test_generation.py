from __future__ import annotations

import ast
import enum
import logging
import platform
import sys
import types
import xml.etree.ElementTree as ET

import pytest

from wazuhtestgen.generator import main as generator_main
from wazuhtestgen.generator import run as generator_run
from wazuhtestgen.internal.evtx import EvtxConverter
from wazuhtestgen.internal.ini import IniConverter, _python_log_literal
from wazuhtestgen.internal.iniParser import IniParser
from wazuhtestgen.internal.naming import identifier
from wazuhtestgen.internal.rule import RuleConverter


def test_identifier_sanitizes_arbitrary_text() -> None:
    assert identifier("Su: failed / root") == "su_failed_root"
    assert identifier("123") == "case_123"
    assert identifier("", fallback="root") == "root"


def test_ini_command_generates_only_pytest_modules(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "input"
    output = tmp_path / "output"
    source.mkdir()
    (source / "su.ini").write_text(
        "[SU failed]\n"
        "log 1 pass = Apr 27 host su[123]: failed\n"
        "rule = 5302\n"
        "alert = 9\n"
        "decoder = su\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generator.py",
            "ini",
            "--input_dir",
            str(source),
            "--output_dir",
            str(output),
        ],
    )

    generator_main()

    assert (output / "test_su_rules.py").is_file()
    assert not (output / "conftest.py").exists()
    assert not (output / "_wazuh_test_support").exists()


def test_ini_converter_generates_native_pytest(tmp_path) -> None:
    source = tmp_path / "su.ini"
    output = tmp_path / "out"
    output.mkdir()

    source.write_text(
        """\
[SU failed]
log 1 pass = Apr 27 host su[123]: failed: user's ''' marker
rule = 5302
alert = 9
decoder = su

[SU negative]
log 1 fail = Apr 27 host su[124]: authentication failure
rule = 5503
alert = 5
decoder = su
""",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    generated = (output / "test_su_rules.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "from wazuhtester import LogtestStatus, send_log" in generated
    assert "pytestmark = pytest.mark.wazuh_logtest" in generated
    assert "def test_rule_match(" in generated
    assert "def test_rule_does_not_match(" in generated
    assert "assert response.status is not LogtestStatus.Error" in generated


def test_ini_converter_excludes_user_ini(tmp_path) -> None:
    source = tmp_path / "user.ini"
    output = tmp_path / "out"
    output.mkdir()
    stale = output / "test_user_rules.py"
    stale.write_text("stale\n", encoding="utf-8")

    source.write_text(
        """\
[User is considered an alias for the static user field]
log 1 pass = { "user": "root" }
rule = 999286
alert = 3
decoder = json
""",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    assert not stale.exists()


def test_ini_converter_excludes_openscap_notapplicable_case(tmp_path) -> None:
    source = tmp_path / "oscap.ini"
    output = tmp_path / "out"
    output.mkdir()

    source.write_text(
        """\
[OpenSCAP rule notapplicable]
log 1 pass = oscap: result: "notapplicable"
rule = 81523
alert = 0
decoder = oscap

[OpenSCAP rule fixed]
log 1 pass = oscap: result: "fixed"
rule = 81524
alert = 3
decoder = oscap
""",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    generated = (output / "test_oscap_rules.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "openscap_rule_notapplicable" not in generated
    assert "openscap_rule_fixed" in generated
    assert "'81524'" in generated


def test_ini_parser_accepts_single_legacy_unkeyed_log(tmp_path) -> None:
    source = tmp_path / "legacy.ini"
    log = (
        'oscap: msg: "xccdf-result", scan-id: "0011477050403", '
        'result: "notapplicable", references: "https://example.test/?a=b".'
    )
    source.write_text(
        f"[Legacy]\n{log}\nrule = 81523\nalert = 0\ndecoder = oscap\n",
        encoding="utf-8",
    )

    cases = IniParser().parse(str(source))

    assert len(cases) == 1
    assert cases[0].logs == (log,)
    assert cases[0].condition == "pass"


def test_ini_parser_rejects_ambiguous_unkeyed_logs(tmp_path) -> None:
    source = tmp_path / "ambiguous.ini"
    source.write_text(
        "[Ambiguous]\n"
        "first bare log\n"
        "second bare log\n"
        "rule = 1\n"
        "alert = 0\n"
        "decoder = test\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid unkeyed log data"):
        IniParser().parse(str(source))


def test_ini_parser_groups_only_repeated_log_keys(tmp_path) -> None:
    source = tmp_path / "frequency.ini"
    source.write_text(
        """\
[Frequency]
log 1 pass = first
log 1 pass = second
log 1 pass = third
rule = 100001
alert = 10
decoder = test

[Independent]
log 1 pass = alpha
log 2 pass = beta
rule = 100002
alert = 5
decoder = test
""",
        encoding="utf-8",
    )

    cases = IniParser().parse(str(source))

    assert [case.logs for case in cases] == [
        ("first", "second", "third"),
        ("alpha",),
        ("beta",),
    ]


def test_ini_converter_generates_multiple_log_fixture(tmp_path) -> None:
    source = tmp_path / "frequency.ini"
    output = tmp_path / "out"
    output.mkdir()
    source.write_text(
        """\
[Frequency]
log 1 pass = first
log 1 pass = second
log 1 pass = third
rule = 100001
alert = 10
decoder = test
""",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    generated = (output / "test_frequency_rules.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert (
        "from wazuhtester import LogtestStatus, send_log, send_multiple_logs"
        in generated
    )
    assert "def test_rule_match_multiple_logs(" in generated
    assert 'r"""first"""' in generated
    assert 'r"""second"""' in generated
    assert 'r"""third"""' in generated
    assert "responses = send_multiple_logs(list(logs))" in generated
    assert "response = responses[-1]" in generated


def test_ini_converter_preserves_backslashes_without_double_escaping(tmp_path) -> None:
    source = tmp_path / "windows.ini"
    output = tmp_path / "out"
    output.mkdir()
    log = r'{"win":{"eventdata":{"image":"C:\\\\Windows\\\\System32\\\\cmd.exe"}}}'

    source.write_text(
        "[Windows path]\n"
        f"log 1 pass = {log}\n"
        "rule = 61603\n"
        "alert = 0\n"
        "decoder = json\n",
        encoding="utf-8",
    )

    IniConverter().convert(str(source), str(output))

    generated = (output / "test_windows_rules.py").read_text(encoding="utf-8")
    tree = ast.parse(generated)
    constants = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]

    assert log in constants
    assert log in generated
    assert r"C:\\\\\\\\Windows" not in generated


@pytest.mark.parametrize(
    "log",
    [
        "type=ANOM_EXEC msg=audit(1222174623.498:608): msg='failed'",
        "%ASA-5-111010: User 'pgskyadm' executed 'terminal pager 0'",
        "dovecot: Support not compiled in for passdb driver 'ldap'",
        "Unable to load config file 'cel.conf'",
        "redis/client.rb:228:in `read'",
        "Failed opening required 'includes/SkinTemplate.php'",
        'message ending in "double quote"',
        "'message starting with single quote",
        '"message starting with double quote',
        "contains '''triple single quotes'''",
        'contains """triple double quotes"""',
        "ends with one backslash\\",
    ],
)
def test_python_log_literal_handles_quote_boundaries(log: str) -> None:
    literal = _python_log_literal(log)

    ast.parse(f"value = {literal}")
    assert ast.literal_eval(literal) == log


@pytest.mark.parametrize("count", range(1, 9))
def test_python_log_literal_preserves_backslash_runs(count: int) -> None:
    log = "before" + ("\\" * count) + "after"
    literal = _python_log_literal(log)

    ast.parse(f"value = {literal}")
    assert ast.literal_eval(literal) == log
    assert ast.literal_eval(literal).count("\\") == count


class _FakeStatus(enum.Enum):
    RuleMatch = "rule-match"
    Error = "error"


def test_ini_fail_case_negates_complete_expected_tuple(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "negative.ini"
    output = tmp_path / "out"
    output.mkdir()
    source.write_text(
        """\
[Negative]
log 1 fail = example
rule = 5503
alert = 5
decoder = su
""",
        encoding="utf-8",
    )
    IniConverter().convert(str(source), str(output))
    generated = (output / "test_negative_rules.py").read_text(encoding="utf-8")

    response_box = {
        "response": types.SimpleNamespace(
            status=_FakeStatus.RuleMatch,
            decoder="su",
            rule_id="5503",
            rule_level=5,
        )
    }
    fake_wazuhtester = types.ModuleType("wazuhtester")
    fake_wazuhtester.LogtestStatus = _FakeStatus
    fake_wazuhtester.send_log = lambda _log: response_box["response"]
    monkeypatch.setitem(sys.modules, "wazuhtester", fake_wazuhtester)

    namespace: dict[str, object] = {}
    exec(compile(generated, "generated_test.py", "exec"), namespace)  # noqa: S102
    test_function = namespace["test_rule_does_not_match"]

    with pytest.raises(AssertionError):
        test_function("example", "su", "5503", 5)

    response_box["response"] = types.SimpleNamespace(
        status=_FakeStatus.RuleMatch,
        decoder="pam",
        rule_id="5503",
        rule_level=5,
    )
    test_function("example", "su", "5503", 5)

    response_box["response"] = types.SimpleNamespace(
        status=_FakeStatus.Error,
        decoder=None,
        rule_id=None,
        rule_level=None,
    )
    with pytest.raises(AssertionError):
        test_function("example", "su", "5503", 5)


def test_rule_converter_generates_skipped_pytest_templates(tmp_path) -> None:
    source = tmp_path / "rules"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()

    (source / "example.xml").write_text(
        """\
<group name="example,">
  <rule id="100001" level="7">
    <description>Example detection</description>
    <groups>authentication_failed,</groups>
  </rule>
</group>
""",
        encoding="utf-8",
    )

    RuleConverter().convert(str(source), str(output))

    generated = (output / "test_example.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "@pytest.mark.skip" in generated
    assert "def test_rule_100001() -> None:" in generated
    assert "assert response.rule_id == '100001'" in generated
    assert "'authentication_failed' in response.rule_groups" in generated


def test_rule_converter_propagates_invalid_xml(tmp_path) -> None:
    source = tmp_path / "rules"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    (source / "broken.xml").write_text(
        '<group name="broken,"><rule id="100001" level="7">',
        encoding="utf-8",
    )

    with pytest.raises(ET.ParseError):
        RuleConverter().convert(str(source), str(output))

    assert not (output / "test_broken.py").exists()


def test_rule_converter_rejects_output_name_collisions(tmp_path) -> None:
    source = tmp_path / "rules"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    rule = '<rule id="100001" level="7"><description>x</description></rule>'
    (source / "foo-bar.xml").write_text(rule, encoding="utf-8")
    (source / "foo_bar.xml").write_text(
        rule.replace("100001", "100002"), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="rule output module name collision"):
        RuleConverter().convert(str(source), str(output))


def test_rule_converter_rejects_duplicate_test_names(tmp_path) -> None:
    source = tmp_path / "rules"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    (source / "duplicate.xml").write_text(
        """\
<rule id="100001" level="7"><description>one</description></rule>
<rule id="100001" level="8"><description>two</description></rule>
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="rule test function name collision"):
        RuleConverter().convert(str(source), str(output))


class _FakeEvtxToJson:
    def to_json(self, _path):
        return iter(
            [
                '{"win":{"system":{"eventID":"1"}}}',
                '{"win":{"system":{"eventID":"3"}}}',
            ]
        )


def _evtx_converter() -> EvtxConverter:
    converter = object.__new__(EvtxConverter)
    converter.converter = _FakeEvtxToJson()
    return converter


def test_evtx_converter_generates_root_pytest_template(tmp_path) -> None:
    source = tmp_path / "evtx"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    (source / "scenario.evtx").write_bytes(b"placeholder")

    _evtx_converter().convert(str(source), str(output))

    generated = (output / "test_root.py").read_text(encoding="utf-8")
    ast.parse(generated)

    assert "import unittest" not in generated
    assert "import pytest" in generated
    assert "from wazuhtester import send_multiple_logs" in generated
    assert (
        "@pytest.mark.skip(reason='Define expected detections for scenario.evtx')"
        in generated
    )
    assert "def test_scenario() -> None:" in generated
    assert "T1021.001" not in generated


def test_evtx_converter_rejects_function_name_collisions(tmp_path) -> None:
    source = tmp_path / "evtx"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    (source / "attack-one.evtx").write_bytes(b"one")
    (source / "attack_one.evtx").write_bytes(b"two")

    with pytest.raises(ValueError, match="EVTX test function name collision"):
        _evtx_converter().convert(str(source), str(output))


def test_evtx_converter_rejects_output_name_collisions(tmp_path) -> None:
    source = tmp_path / "evtx"
    output = tmp_path / "out"
    source.mkdir()
    output.mkdir()
    first = source / "foo-bar"
    second = source / "foo_bar"
    first.mkdir()
    second.mkdir()
    (first / "one.evtx").write_bytes(b"one")
    (second / "two.evtx").write_bytes(b"two")

    with pytest.raises(ValueError, match="EVTX output module name collision"):
        _evtx_converter().convert(str(source), str(output))


def test_evtx_converter_rejects_non_windows(monkeypatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")

    with pytest.raises(RuntimeError, match="only on Windows"):
        EvtxConverter()


def test_cli_reports_runtime_errors_without_traceback(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    source = tmp_path / "input"
    output = tmp_path / "output"
    source.mkdir()
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "wazuhtestgen",
            "evtx",
            "--input_dir",
            str(source),
            "--output_dir",
            str(output),
        ],
    )
    monkeypatch.setattr(logging, "basicConfig", lambda **_kwargs: None)

    assert generator_run() == 2
    captured = capsys.readouterr()
    assert "the evtx command requires Windows" in captured.err
    assert not output.exists()
    assert "Traceback" not in captured.err
