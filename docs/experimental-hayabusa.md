# Experimental Hayabusa-assisted EVTX rule generation

Status: experimental design; no runtime implementation yet.

## Purpose

Correlate Hayabusa Sigma-compatible detections against the **same** EVTX records converted into Wazuh-compatible JSON by wazuhevtx. Generate evidence-backed suggestions for Wazuh rule tests, atomic rule predicates, MITRE ATT&CK tags, and severity review. Do not treat a Hayabusa match as proof that a Wazuh rule will match.

## Compatibility

Hayabusa >=4.0 uses `dfir-timeline`, not `json-timeline`. Prefer JSONL for streaming:

```sh
hayabusa dfir-timeline --directory /path/to/evtx --output-type jsonl --profile verbose --output timeline.jsonl
```

Invoke `hayabusa` via `shutil.which` and `subprocess.run([...], shell=False, check=True)`. Detect CLI capability/version rather than silently assuming older syntax. Accept precomputed timelines to permit offline analysis and tests on Linux, although existing wazuhevtx-based EVTX extraction remains Windows-only.

## Correlation

The canonical event identity is a composite, not an Event ID or timestamp:

```
(source EVTX relative path, Computer, Channel, EventRecordID)
```

Record IDs are scoped to individual logs and are NOT globally unique. Preserve original paths in a manifest when enumerating EVTX. Normalize case for Windows channel/computer as needed and separators for filenames. Do not infer a match from timestamp alone. Treat missing source metadata, inconsistent field values, non-unique joins, or multiple plausible files as unresolved, not as successful correlations.

Wazuh-side fields to validate against real output: `win.system.computer`, `win.system.channel`, `win.system.eventRecordID`, `win.system.eventID`, `win.system.providerName`. Hayabusa verbose output includes `Computer`, `Channel`, `EventID`, `RecordID`, `EvtxFile`, `RuleID`, `RuleTitle`, `RuleFile`, `Level`, `MitreTags`, `MitreTactics`, `Details`, `ExtraFieldInfo`. Validate actual JSON field shapes on a fixture before implementing adapters.

A single Windows event can trigger multiple Hayabusa rules. Preserve the many-to-one association and deduplicate by (event key, Hayabusa rule UUID); do not conflate multiple detections or collapse distinct records.

## Separation of responsibilities

- `wazuhevtx`: authoritative Wazuh-compatible replay fixture.
- Hayabusa: Sigma-derived hypotheses and source rule metadata.
- `wazuhtestgen`: correlation, evidence, review suggestions, and editable pytest templates.
- `wazuhtester`: ground-truth logtest execution and assertions.

Preserve existing `evtx` command behavior as default. Put Hayabusa behind an explicit opt-in switch or separate `hayabusa` command. No mandatory dependency or Windows-only import during Linux CLI usage.

## Candidate classes

1. **Atomic**: one matched event provides observable conditions. Infer possible Wazuh `field` predicates using the **original Wazuh JSON**, not Hayabusa's friendly `Details` keys. Filter by presence, exact values, escape regex metacharacters, and review noisy/volatile fields. Rule output is review-only.
2. **Temporal**: multiple matched events supply a repeated or correlated sequence. A single Hayabusa match is not evidence of temporal behavior. Repetition or timeframe requires per-event timestamps and a defensible grouping key; Wazuh's temporal correlation semantics and `if_matched_*` prerequisites must be validated independently.
3. **Metadata checks**: compare ATT&CK technique IDs against the Wazuh 4.x supported mapping (currently v13.1), and severity as an explicit advisory policy, not a direct Hayabusa Level-to-Wazuh-level equivalence.

Hayabusa Sigma compatibility is not universal and its rules may be translated or enriched beyond the original Sigma definitions. Retain rule UUID, rule file, title, selected profile, and source version. Do not label these candidates authoritative Sigma translations.

## Output

Proposed per-run artifacts:

```
output/
  timeline.jsonl              # optional, generated or supplied
  event-manifest.jsonl        # EVTX provenance, stable event keys
  hayabusa-correlations.jsonl # event-to-detection associations and unresolved rows
  suggestions.json            # atomic/temporal/metadata candidate assessments
  test_*.py                   # editable pytest tests, skipped until reviewed
```

Never bake suggestions into live Wazuh rules or silently unskip tests. Prefer compact manifest or external fixture files over embedded enormous JSON lists when input sizes warrant it.

## Acceptance tests

- Two EVTX files with identical RecordID but different paths/channels/computers remain distinct.
- Multiple Hayabusa rule UUIDs matching one EVTX record are preserved.
- Hayabusa rows without an exact unambiguous source/event key are reported as unresolved.
- A Hayabusa finding cannot manufacture a Wazuh assertion or turn a skipped template into a passing test.
- Metadata fields retain raw values, and ATT&CK/severity discrepancies are advisory.
- Paths containing spaces work; no shell interpolation; missing executable returns a clear error.
- Existing INI/rule/EVTX generation remains unchanged when Hayabusa is disabled.
- Fixture parsing and correlation run on Python 3.9 through 3.14 without depending on a local Hayabusa installation.
- End-to-end Windows tests use actual wazuhevtx output and a version-pinned Hayabusa fixture.
- Ensure event data and logs are not transmitted to a service.

## Implementation sequence

1. Capture golden output fixtures for current Hayabusa (>=4.0) and wazuhevtx.
2. Implement input adapters + strict join and diagnostic counters; test completely offline.
3. Add opt-in Hayabusa subprocess runner + timeline import.
4. Generate evidence-ranked atomic candidates, advisory metadata comparisons, and skipped tests.
5. Experiment with temporal candidate mining only after an explicit sequence model and Wazuh logtest oracle are available.
