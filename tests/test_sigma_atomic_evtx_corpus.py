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
    SigmaConverter, correlate, run_zircolite,
)

REPO = "arniki/atomic-evtx"
REVISION = "8de5fa8f158b4d72d1e3c6f07053162c90ee6238"
SAMPLES = {
    "attack_sysmon": (
        "ttp_evtx/T1059.003-1/"
        "T1059.003-1_Microsoft-Windows-Sysmon_Operational.evtx",
        "43db42f98cccf6d387078b710990554a242b5a3b",
    ),
    "benign_powershell": (
        "benign_activity_logs/powershell_820.evtx",
        "a58139976d030f2c64d0bd2e1c6dbd540c883964",
    ),
}
FIXTURES = Path(__file__).resolve().parent / "fixtures/sigma"


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
        EvtxToJson(), ruleset=str(ruleset), config=_mapping_config(),
    ).convert(str(source.parent), str(output))

    generated = (output / "test_sigma_sysmon.py").read_text(encoding="utf-8")
    tree = ast.parse(generated)
    test_functions = [
        node for node in tree.body
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
        source, ruleset=str(FIXTURES / "atomic_evtx_benign_join.json"),
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
