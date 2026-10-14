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

## Runtime

Requires Windows for wazuhevtx. The optional `zircolite` extra installs
upstream Zircolite 4.5+ together with pytest and wazuhtester. This extra
requires Python >=3.11 by upstream package metadata and deliberately cannot
resolve on Python 3.9 or 3.10. The base wazuhtestgen package retains Python
>=3.9 support. The integration executes `sys.executable -m zircolite` in a
subprocess, so no standalone Zircolite executable or PATH lookup is needed.
This separates the application-level state of Zircolite from the generator
and avoids private API stability dependencies.

Example:

```console
wazuhtestgen zircolite --input_dir C:\\EVTX --output_dir tests \
  --zircolite-executable Zircolite.exe
```

An explicit ruleset can be supplied with `--ruleset`. The adapter invokes
`python -m zircolite --events <one EVTX file> --outfile <temporary JSON> --quiet --no-parallel`.
It uses a deterministic per-file context and does not depend on a shared
external SQLite database.

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
