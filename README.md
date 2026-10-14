# wazuhtestgen

A small generator for creating pytest-formatted Wazuh rule tests from Wazuh INI regression tests, Windows Event Log (EVTX) files, or Wazuh rule XML.

The generated tests target the public `wazuhtester` API instead of the old `wazuh-devenv/internal.logtest` module. This keeps test content independent from the development environment and allows the generated tests to run anywhere `wazuhtester`, pytest, and a reachable Wazuh logtest daemon are available.

## Rationale

Wazuh ships regression-test content in an INI format. `wazuhtestgen` converts that content into ordinary pytest modules so detection engineers can extend the tests with Python assertions, fixtures, parametrization, and other pytest features.

INI files contain complete expected outcomes, so the converter emits runnable parameterized tests. Positive and negative cases are generated separately. Negative cases also verify that Wazuh did not return an error before accepting that a particular rule did not match.

EVTX and rule XML are different. They provide source material but do not contain enough information to infer the intended detection outcome. Those converters therefore generate editable pytest templates marked as skipped. The detection engineer supplies the expected rule IDs, levels, groups, MITRE ATT&CK techniques, or other assertions and then removes the skip marker.

## Requirements

`wazuhtestgen` requires Python 3.9 or newer. EVTX conversion additionally requires Windows; the `wazuhevtx` dependency is installed automatically on Windows. The experimental `zircolite` command requires the optional `zircolite` extra, which pins an upstream Zircolite Git revision alongside pytest and `wazuhtester`. Zircolite requires Python 3.11+; the regular installation remains compatible with Python 3.9+. The extra is for source-based experiments, not yet suitable for PyPI publishing.

## Generated test dependencies

Generated tests use:

```python
import pytest

from wazuhtester import LogtestStatus, send_log
```

The generated modules are marked with:

```python
pytestmark = pytest.mark.wazuh_logtest
```

The `wazuhtester` pytest plugin can therefore skip tests that require Wazuh when the logtest daemon is unavailable, or fail the session when configured to require it.

## Usage

Top level:

```text
usage: wazuhtestgen [-h] [--debug] {ini,evtx,zircolite,rule} ...

wazuhtestgen generates pytest-formatted Wazuh rule tests from Wazuh
INI regression tests, Windows EVTX files, or Wazuh rule XML.

positional arguments:
  {ini,evtx,zircolite,rule}
    ini             Generate pytest tests from Wazuh INI regression tests.
    evtx            Generate editable pytest templates from EVTX files.
    zircolite       Generate executable atomic detection pytest drafts using Zircolite.
    rule            Generate editable pytest templates from Wazuh rule XML files.

options:
  -h, --help        show this help message and exit
  --debug, -d       Enable debug logging.
```

INI:

```text
wazuhtestgen ini --input_dir INPUT_DIR --output_dir OUTPUT_DIR
```

EVTX:

```text
wazuhtestgen evtx --input_dir INPUT_DIR --output_dir OUTPUT_DIR
```

Zircolite (experimental):

```text
python -m pip install -e ".[zircolite]"
wazuhtestgen zircolite --input_dir INPUT_DIR --output_dir OUTPUT_DIR \
  --ruleset PATH_TO_RULESET --zircolite-config PATH_TO_ZIRCOLITE_CONFIG
```

See [experimental Zircolite design](docs/experimental-zircolite.md) for the required Zircolite ruleset and field-mapping assets, Sigma metadata mapping, the atomic-only scope, and Python 3.11+ restriction.

Wazuh rules:

```text
wazuhtestgen rule --input_dir INPUT_DIR --output_dir OUTPUT_DIR
```

## Execution environment

`wazuhtestgen` only generates pytest modules. Generated tests do not modify the
Wazuh installation, copy rules or decoders into the manager, or write under
`/var/ossec/ruleset`.

When using the upstream Wazuh regression corpus with `wazuhdevenv`, prepare the
manager with `wazuhdevenv init` before running the generated tests.
`wazuhdevenv` owns privileged manager configuration, including the Windows rule
60000 JSON-decoding adjustment and the development workspace bind mounts.

## INI output

A Wazuh INI file is converted into parameterized pytest tests. For example:

```python
import pytest

from wazuhtester import LogtestStatus, send_log


pytestmark = pytest.mark.wazuh_logtest


@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            "Apr 27 15:22:23 host su[123]: failed: changing from user to root",
            "su",
            "5302",
            9,
            id="su_failed",
        ),
    ],
)
def test_rule_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level
```

Fail cases are emitted separately:

```python
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
        pytest.param(
            "example log",
            "su",
            "5503",
            5,
            id="rule_must_not_match",
        ),
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )
```

## Rule XML output

Each rule becomes an editable skipped test:

```python
@pytest.mark.skip(reason="Provide a log matching rule 100001")
def test_rule_100001() -> None:
    log = "TODO: provide a matching log here"
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.rule_id == "100001"
```

Supply an original matching log, review the generated expectations, and remove the skip marker.

## EVTX output

Each EVTX file becomes a skipped scenario test containing the JSON events extracted from that file:

```python
@pytest.mark.skip(reason="Define expected detections for scenario.evtx")
def test_scenario() -> None:
    logs = [
        '{"win": {"system": {"eventID": "1"}}}',
    ]

    responses = send_multiple_logs(logs, log_format="json")

    assert len(responses) == len(logs)

    # TODO: Add scenario-specific assertions.
```

The generator deliberately does not invent a rule ID, MITRE ATT&CK technique, or other expected detection from the EVTX contents.

## Experimental Zircolite atomic output

The `zircolite` command consumes the same EVTX files as `wazuhevtx`, runs Zircolite against each, and joins atomic Sigma detections to the Wazuh-compatible JSON events. It produces runnable parametrized pytest cases with proposed minimum alert severity and MITRE ATT&CK IDs. Initial assertion failures are expected in Red–Green–Refactor TDD. Aggregate/correlation Sigma results are excluded until temporal replay semantics can be implemented reliably. The existing `evtx` command remains skipped-template generation and is unchanged.

## Generated output directory

Files under `output/` are generated artifacts rather than generator source. A checked-in snapshot can therefore reflect an older generator version. Regenerate output from the authoritative INI, EVTX, or rule inputs when validating the current generator behavior.

## Notes

The tests extracted from [INI files](https://github.com/wazuh/wazuh/tree/4.14.10/ruleset/testing/tests) have some exceptions.

### Upstream corpus exclusions

`overwrite.ini` depends on test-only overwrite rules and decoders. It is not a
standalone built-in-rule regression test and must still be removed before generation:

```bash
rm /path/to/ruleset/testing/tests/overwrite.ini
```

`user.ini` depends on test-only rule `999286` from
`ruleset/testing/ruleset/test_rules.xml`. The INI converter excludes this file
automatically and removes a stale `test_user_rules.py` from the output directory
if one exists.

### oscap.ini

The upstream `oscap.ini` file contains one legacy test case without the normal
`log <number> <condition> =` prefix. The parser accepts a single unkeyed line in a section
as a positive log entry, matching that upstream exception without replacing or truncating
the log content.

The `OpenSCAP rule notapplicable` case is excluded from generated pytest output.
Its upstream expected rule does not match the standalone built-in-rule corpus
qualification environment. Other `oscap.ini` cases are still generated normally.

### Commented out tests

The test conditions within `unbound.ini` and `win_application.ini` are commented out and the files are excluded as a whole.

### Regex pattern tests

The test files with `test_*.ini` pattern are for pattern matching (OS_Regex, OS_Match, PCRE2) not rule tests, and files are excluded as a whole.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
