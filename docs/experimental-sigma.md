# Experimental Sigma atomic EVTX pytest generation

## Scope

The experimental Sigma processor uses Zircolite to evaluate *atomic* Sigma rules. wazuhevtx remains the
source of Wazuh-compatible JSON fixtures. wazuhtestgen joins Zircolite's
flattened `matches` records to those fixtures and writes executable,
parametrized pytest tests. Sigma correlations are deliberately deferred.

The test contract is: one event must produce an alert whose level is at
least the proposed minimum and whose MITRE ATT&CK IDs contain every
expected technique.

Tests are Red-phase, best-effort templates. The installed Wazuh ruleset
determines the final outcome. No Wazuh rule IDs are assumed.

## Runtime and opt-in dependency restrictions

The standard wazuhtestgen package retains Python >=3.9. The experimental
`[sigma]` extra opts into Python >=3.11, upstream Zircolite's native
build/dependency requirements, and pytest. `wazuhtester` is an extra dependency
only on Linux because it requires a local Wazuh `wazuh-logtest` Unix socket.
Windows generates templates; Linux executes them using `wazuhtester`. This branch pins
Zircolite's source revision
`2557ed1672e9f0281fcb2937bf38dd49cbc52d8e` because a Zircolite 4.5.x
distribution is not currently available on PyPI. Direct VCS dependencies
are an **experimental source-install mechanism**; they cannot be shipped
unchanged in a future PyPI release of wazuhtestgen.

The selected Sigma backend's Python package does **not** reliably include its
separate `config/` and `rules/` assets. Use an upstream Zircolite source
checkout for those files. Both are required to avoid silently running with
incorrect field mappings or without a ruleset.

### Upstream resolver conflict

Zircolite 4.5.0 requires `pysigma>=2,<3`, but the current releases of
`pysigma-pipeline-sysmon` and `pysigma-pipeline-windows` still declare
`pysigma<2`. Their metadata is inconsistent with Zircolite's pySigma 2
configuration. Zircolite documents using a dependency override in PDM/uv,
and explicitly notes that a standard resolver cannot reconcile the bounds.

The experimental `requirements/sigma-overrides.txt` replaces these
conflicting bounds with `pysigma>=2,<3`. Use `uv pip install --override`,
**not** `pip install -c` (constraints only tighten dependencies and cannot
override an incompatible upper bound). This bypasses pipeline metadata,
so it requires integration testing before the experimental mode is released.
Ordinary `pip install -e ".[sigma]"` will still fail while upstream metadata
remains incompatible. Standard `wazuhtestgen` installations are unaffected.

Example (PowerShell, Windows, Python 3.11+, from the wazuhtestgen checkout):

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install "uv>=0.9,<1"
.\.venv\Scripts\uv.exe pip install --python .\.venv\Scripts\python.exe --override requirements/sigma-overrides.txt -e ".[sigma]"
git clone https://github.com/wagga40/Zircolite.git C:\tools\Zircolite
git -C C:\tools\Zircolite checkout 2557ed1672e9f0281fcb2937bf38dd49cbc52d8e
.\.venv\Scripts\wazuhtestgen.exe sigma `
  --input_dir C:\EVTX `
  --output_dir C:\tests `
  --ruleset C:\tools\Zircolite\rules\rules_windows_merged.json `
  --mapping-config C:\tools\Zircolite\config\config.yaml
```

### Running the generated tests

Generated `test_sigma_*.py` modules are **not** intended to execute on
Windows: they import `wazuhtester`, which only supports Linux and expects
access to the manager's local `wazuh-logtest` Unix socket. Transfer the
generated test modules to a Linux environment with Wazuh and `wazuhtester`
installed, then run pytest there. Failure of a Wazuh assertion is the intended
Red stage; inability to reach the logtest socket is an infrastructure error.

For reproducible results, use source assets from the same revision as the
pinned Zircolite library rather than a floating `master` checkout.
The Python module is invoked using
`sys.executable -m zircolite --events ... --ruleset ... --config ...`.
No standalone executable is needed. The subprocess isolates Zircolite's
state without coupling to its private processing APIs.

## Input format

The Zircolite backend returns a JSON array of rule objects. Atomic objects contain
`id`, `title`, `rule_level`, `tags`, and `matches`. Each match contains
a flattened event, including `Computer`, `Channel`, `EventID`,
`EventRecordID`, and ordinarily `OriginalLogfile` with the source EVTX name.

Correlation results carry `result_type: "correlation"` and are entirely
ignored. The exact event join is:
`(Computer, Channel, EventRecordID, EventID)`.
`OriginalLogfile`, when provided, must correspond to the EVTX currently
being processed. Case-insensitive matching is used for Computer, Channel
and file basename. Ambiguous/unmatched records are reported and omitted;
no approximate matching by timestamp is performed.

Each unique (event, Sigma rule ID) match generates its own pytest parameter.
The same Windows event may become multiple independent parameters when
several distinct Sigma rules matched it.

## Metadata

The built-in Sigma severity policy is:
informational=3, low=5, medium=7, high=10, critical=13.
Values are proposed minimum alert levels, never official severity equivalences.

ATT&CK tags are normalized to `Txxxx`/`Txxxx.xxx`, ignoring non-technique
labels. The small static `attack_mapping.py` overrides only confirmed
version-incompatibility cases. Unmapped techniques retain the same ID;
the exception map is intentionally empty until verified examples exist.

Missing severity or ATT&CK technique metadata results in a failing,
user-editable assertion, not a misleading Green result.

## Backend integration

Zircolite exports `ZircoliteCore`, `RulesetHandler`, and reusable processing
components. The user opts into their dependency graph with the `sigma`
extra, so direct imports are feasible. However, the public application entry
point is more stable than wiring the full processing pipeline to internal
classes. A direct in-process provider can be explored after verifying the
executable-module output contract.


## Real EVTX fixture provenance and validation

The experimental Windows CI job can run a **real, offline-convertible EVTX
join probe**. The source is
[mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
(CC0 1.0), revision `474856008f037ccd42753f02a631b42690195829`,
file `TA0001-Initial access/T1078-Valid accounts/ID4625-failed login with denied access due to account restriction.evtx`
(69,632 bytes), pinned Git blob
`68b9ef68ed7d653472d06106712809843bf0b266`.
The fixture is downloaded only in the opt-in Windows CI test; it is not
redistributed in this repository. It is checked against the blob hash
before processing.

The companion compiled Zircolite JSON rule in
`tests/fixtures/sigma/security_4625_join.json` is deliberately a generic
EventID=4625 predicate. It proves the real EVTX-to-Wazuh JSON extraction,
Zircolite event match, deterministic identity join, and generated pytest
parameter path. It **does not** prove an ATT&CK technique occurred or
validate a production Sigma YAML detection. Such detection-fidelity tests
must use a reviewed predicate with a verified event witness.

Other promising corpora for an extended non-gating suite include
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(GPL-3.0) and
[Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx)
(mixed-origin collection with no confirmed repository-wide license).
Yamato mirrors samples from the other two, so identify duplicates by
Git blob SHA and preserve source provenance. Do not vendor mixed-license
files as though they were all CC0. Treat folder ATT&CK technique names
as informal scenario annotations, not as ground truth for expected
atomic rule matches.

Correlations, temporal events, and multi-event ATT&CK scenarios remain
outside the scope of these atomic acceptance tests.

## Validation status

Offline unit tests use mocked Sigma backend outputs and wazuhevtx records.
Real Windows EVTX / Sigma backend 4.5.0 end-to-end replay has not yet been
validated. Actual output field spellings, CLI launch behaviour and
operationally safe ruleset selection must be confirmed before release.
