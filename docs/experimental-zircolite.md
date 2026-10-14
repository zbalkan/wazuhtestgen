# Experimental Zircolite atomic EVTX pytest generation

## Scope

Zircolite supplies *atomic* Sigma matches and metadata. wazuhevtx remains the
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
`[zircolite]` extra opts into Python >=3.11, upstream Zircolite's native
build/dependency requirements, pytest, and wazuhtester. This branch pins
Zircolite's source revision
`2557ed1672e9f0281fcb2937bf38dd49cbc52d8e` because a Zircolite 4.5.x
distribution is not currently available on PyPI. Direct VCS dependencies
are an **experimental source-install mechanism**; they cannot be shipped
unchanged in a future PyPI release of wazuhtestgen.

The Python package install does **not** reliably include Zircolite's
separate `config/` and `rules/` assets. Use an upstream Zircolite source
checkout for those files. Both are required to avoid silently running with
incorrect field mappings or without a ruleset.

Example (Windows, Python 3.11+):

```powershell
python -m pip install -e ".[zircolite]"
git clone https://github.com/wagga40/Zircolite.git C:\tools\Zircolite
git -C C:\tools\Zircolite checkout 2557ed1672e9f0281fcb2937bf38dd49cbc52d8e
wazuhtestgen zircolite `
  --input_dir C:\EVTX `
  --output_dir C:\tests `
  --ruleset C:\tools\Zircolite\\rules\\rules_windows_merged.json `
  --zircolite-config C:\tools\Zircolite\\config\\config.yaml
```

For reproducible results, use source assets from the same revision as the
pinned Zircolite library rather than a floating `master` checkout.
The Python module is invoked using
`sys.executable -m zircolite --events ... --ruleset ... --config ...`.
No standalone executable is needed. The subprocess isolates Zircolite's
state without coupling to its private processing APIs.

## Input format

Zircolite returns a JSON array of rule objects. Atomic objects contain
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

## Future Python library option

Zircolite exports `ZircoliteCore`, `RulesetHandler`, and reusable processing
components. The user opts into their dependency graph with the `zircolite`
extra, so direct imports are feasible. However, the public application entry
point is more stable than wiring the full processing pipeline to internal
classes. A direct in-process provider can be explored after verifying the
executable-module output contract.

## Validation status

Offline unit tests use mocked Zircolite outputs and wazuhevtx records.
Real Windows EVTX / Zircolite 4.5.0 end-to-end replay has not yet been
validated. Actual output field spellings, CLI launch behaviour and
operationally safe ruleset selection must be confirmed before release.
