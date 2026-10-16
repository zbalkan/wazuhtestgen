"""Pinned real-EVTX smoke tests from arniki/atomic-evtx.

These probes verify event parsing, source correlation, and generated pytest
structure. They do NOT determine whether an Atomic Red Team technique actually
executed or whether a benign event should trigger a specific security rule.
The repository's root does not declare a license, so no EVTX bytes are vendored.
"""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

import pytest

from wazuhtestgen.internal.sigma import (
    SigmaConverter,
    correlate,
    run_zircolite,
)

REPO = "arniki/atomic-evtx"
REVISION = "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
SAMPLES = {
    "attack_sysmon": (
        "ttp_evtx/T1059.003-1/T1059.003-1_Microsoft-Windows-Sysmon_Operational.evtx",
        "43db42f98cccf6d387078b710990554a242b5a3b",
    ),
    "benign_powershell": (
        "benign_activity_logs/powershell_820.evtx",
        "a58139976d030f2c64d0bd2e1c6dbd540c883964",
    ),
    "attack_powershell": (
        "ttp_evtx/T1560-1/T1560-1_Windows PowerShell.evtx",
        "dd2e8a7a67158890d06a457f78ac4a240632fe0e",
    ),
}
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _get_sample(name: str, destination: Path) -> Path:
    path, expected_sha = SAMPLES[name]
    url = f"https://raw.githubusercontent.com/{REPO}/{REVISION}/{quote(path, safe='/')}"
    with urlopen(url, timeout=120) as request:
        content = request.read()
    git_blob = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    actual = hashlib.sha1(git_blob).hexdigest()
    assert actual == expected_sha, (
        f"Pinned {name} EVTX source changed ({actual}); review provenance"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    return destination


def _mapping_config() -> str:
    value = os.environ.get("SIGMA_ZIRCOLITE_CONFIG")
    assert value, "Set SIGMA_ZIRCOLITE_CONFIG to Zircolite config.yaml"
    assert Path(value).is_file(), value
    return value


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SIGMA_REAL_EVTX") != "1",
    reason="Real Atomic-EVTX corpus tests require explicit Windows CI opt-in",
)
def test_attack_sysmon_evtx_generates_parametrized_atomic_case(tmp_path: Path) -> None:
    from wazuhevtx.evtx2json import EvtxToJson

    source = _get_sample("attack_sysmon", tmp_path / "input" / "Sysmon.evtx")
    output = tmp_path / "output"
    ruleset = FIXTURES / "atomic_evtx_sysmon_join.json"
    SigmaConverter(
        EvtxToJson(),
        ruleset=str(ruleset),
        config=_mapping_config(),
    ).convert(str(source.parent), str(output))

    generated = (output / "test_sigma_sysmon.py").read_text(encoding="utf-8")
    tree = ast.parse(generated)
    test_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_sigma_atomic"
    ]
    assert len(test_functions) == 1, (
        f"Atomic Sysmon fixture must produce an executable test:\n{generated[:1500]}"
    )
    assert generated.count("pytest.param(") == 1
    assert "de0a1295-f6cf-4ea4-9d90-e6c6fbcc0d51" in generated
    assert "T1059.003" in generated
    assert "        7," in generated
    assert "# Atomic events unresolved: 0" in generated


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SIGMA_REAL_EVTX") != "1",
    reason="Real Atomic-EVTX corpus tests require explicit Windows CI opt-in",
)
def test_benign_powershell_evtx_parses_and_joins_without_attack_claim(
    tmp_path: Path,
) -> None:
    from wazuhevtx.evtx2json import EvtxToJson

    source = _get_sample("benign_powershell", tmp_path / "input" / "PowerShell.evtx")
    logs = list(EvtxToJson().to_json(source))
    assert logs, "Benign EVTX must yield real Wazuh-compatible events"

    results = run_zircolite(
        source,
        ruleset=str(FIXTURES / "atomic_evtx_benign_join.json"),
        config=_mapping_config(),
    )
    matched, counts = correlate(logs, results, source)
    assert len(matched) == 1, (
        "Benign records must be parsable and uniquely joinable, independent "
        f"of their detection label; results={len(results)}, counts={counts}"
    )
    assert counts["unresolved"] == 0
    assert counts["correlations"] == 0
    assert not matched[0][1].get("tags"), (
        "The benign interoperability probe must not manufacture ATT&CK labels"
    )


@pytest.mark.skipif(
    os.name != "nt" or os.environ.get("SIGMA_REAL_EVTX") != "1",
    reason="Real Atomic-EVTX corpus tests require explicit Windows CI opt-in",
)
def test_same_powershell_predicate_matches_attack_but_not_benign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same provider and same Sigma SQL against two independent EVTX files.

    The probe references a captured command-specific marker. It is not a
    general Sigma rule and does not establish benign behavioral ground truth.
    """
    from wazuhevtx.evtx2json import EvtxToJson

    from wazuhtestgen.internal import sigma as sigma_module

    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    attack = _get_sample(
        "attack_powershell",
        input_dir / "T1560-1_Windows PowerShell.evtx",
    )
    benign = _get_sample(
        "benign_powershell",
        input_dir / "powershell_820.evtx",
    )

    captured: dict[str, list[dict]] = {}
    real_runner = sigma_module.run_zircolite

    def capturing_runner(
        evtx: Path,
        ruleset: str,
        config: str,
        pipelines: tuple[str, ...] = (),
    ) -> list[dict]:
        detections = real_runner(evtx, ruleset, config, pipelines=pipelines)
        captured[evtx.name] = detections
        return detections

    monkeypatch.setattr(sigma_module, "run_zircolite", capturing_runner)
    SigmaConverter(
        EvtxToJson(),
        ruleset=str(FIXTURES / "atomic_evtx_t1560_powershell.json"),
        config=_mapping_config(),
    ).convert(str(input_dir), str(output_dir))

    positive = captured[attack.name]
    negative = captured[benign.name]
    rule_id = "21ad178e-7626-4be9-8dbe-7eeb1e93ca2d"
    assert any(
        result.get("id") == rule_id and result.get("matches") for result in positive
    ), f"Expected an atomic PowerShell command witness, got {positive!r}"
    assert not negative, (
        "The same command predicate must not match the independent benign "
        f"PowerShell corpus: {negative!r}"
    )

    generated_positive = (
        output_dir / "test_sigma_t1560_1_windows_powershell.py"
    ).read_text(encoding="utf-8")
    generated_benign = (output_dir / "test_sigma_powershell_820.py").read_text(
        encoding="utf-8"
    )
    ast.parse(generated_positive)
    ast.parse(generated_benign)
    assert generated_positive.count("pytest.param(") >= 1
    assert rule_id in generated_positive
    assert "T1560" in generated_positive
    assert "# Atomic events unresolved: 0" in generated_positive
    assert "        7," in generated_positive
    assert "def test_sigma_atomic" not in generated_benign
    assert "# No uniquely correlated atomic detections" in generated_benign
