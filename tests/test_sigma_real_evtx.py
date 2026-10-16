"""Opt-in, real EVTX → Zircolite → wazuhevtx → parametrized pytest test.

The upstream fixture is CC0 1.0. We pin both its source revision and Git
blob SHA to prevent a moving public corpus from changing CI expectations.

Only the Windows Sigma integration job sets SIGMA_REAL_EVTX=1. Ordinary
cross-platform tests remain offline and do not need native EVTX parsers.
"""

from __future__ import annotations

import ast
import hashlib
import os
import pathlib
import urllib.parse
import urllib.request

import pytest

from wazuhtestgen.internal.sigma import SigmaConverter

SOURCE = "mdecrevoisier/EVTX-to-MITRE-Attack"
REVISION = "474856008f037ccd42753f02a631b42690195829"
SOURCE_PATH = (
    "TA0001-Initial access/T1078-Valid accounts/"
    "ID4625-failed login with denied access due to account restriction.evtx"
)
GIT_BLOB_SHA1 = "68b9ef68ed7d653472d06106712809843bf0b266"
RULE_UUID = "83b95893-6526-4cf6-ac1d-e93468995316"


@pytest.mark.skipif(
    os.environ.get("SIGMA_REAL_EVTX") != "1" or os.name != "nt",
    reason="Explicit opt-in required; real EVTX generation only runs on Windows",
)
def test_real_evtx_generates_atomic_sigma_cases(tmp_path: pathlib.Path) -> None:
    from wazuhevtx.evtx2json import EvtxToJson

    config_file = os.environ.get("SIGMA_ZIRCOLITE_CONFIG")
    assert config_file, "Set SIGMA_ZIRCOLITE_CONFIG to upstream config.yaml"
    assert pathlib.Path(config_file).is_file(), config_file

    path = urllib.parse.quote(SOURCE_PATH, safe="/")
    url = f"https://raw.githubusercontent.com/{SOURCE}/{REVISION}/{path}"
    with urllib.request.urlopen(url, timeout=90) as request:
        content = request.read()
    git_blob = b"blob " + str(len(content)).encode() + b"\0" + content
    actual_sha = hashlib.sha1(git_blob).hexdigest()
    assert actual_sha == GIT_BLOB_SHA1, (
        "External EVTX fixture changed unexpectedly; do not silently change "
        f"test corpus expectations: {actual_sha}"
    )

    inputs = tmp_path / "input"
    outputs = tmp_path / "output"
    inputs.mkdir()
    (inputs / "Security.evtx").write_bytes(content)
    ruleset = pathlib.Path(__file__).resolve().parent / (
        "fixtures/sigma/security_4625_join.json"
    )
    SigmaConverter(
        EvtxToJson(),
        ruleset=str(ruleset),
        config=config_file,
    ).convert(str(inputs), str(outputs))
    generated = (outputs / "test_sigma_security.py").read_text(encoding="utf-8")
    tree = ast.parse(generated)

    test_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_sigma_atomic"
    ]
    assert len(test_functions) == 1, (
        "Expected a real matched Windows Security record to generate an "
        f"atomic pytest test, not a zero-case module:\n{generated[:2500]}"
    )
    assert generated.count("pytest.param(") >= 1
    assert RULE_UUID in generated
    assert "T1078" in generated
    assert "        7," in generated
    assert "# Atomic events unresolved: 0" in generated
    assert "response.rule_level >= expected_level" in generated
    assert "set(expected_mitre_ids) <= response.rule_mitre_ids" in generated
