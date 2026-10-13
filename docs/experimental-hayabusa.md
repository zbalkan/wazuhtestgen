# Experimental Hayabusa-assisted EVTX rule generation

Status: experimental proof of concept; implementation is incomplete and not end-to-end validated.

## Purpose

Correlate Hayabusa Sigma-compatible detections against the **same** EVTX records converted into Wazuh-compatible JSON by wazuhevtx. Generate executable, best-effort pytest tests for individual atomic Hayabusa matches, with Wazuh-compatible JSON events, minimum alert levels, and ATT&CK tags. Rule predicates or Sigma-to-Wazuh XML conversion are not generated. Do not treat a Hayabusa match as proof that a Wazuh rule will match.

## Compatibility

Hayabusa >=4.0 uses `dfir-timeline`, not `json-timeline`. Prefer JSONL for streaming:

```sh
hayabusa dfir-timeline --directory /path/to/evtx --output-type jsonl --profile verbose --output timeline.jsonl
```

Invoke `hayabusa` via `shutil.which` and `subprocess.run([...], shell=False)` with explicit return-code checks. Use `--disable-abbreviations` so `Security` is not emitted as `Sec`, permitting an exact Windows channel join. The generator invokes Hayabusa once per EVTX input file. Detect CLI capability/version rather than silently assuming older syntax. Accept precomputed timelines to permit offline analysis and tests on Linux, although existing wazuhevtx-based EVTX extraction remains Windows-only.

## Correlation

The canonical event identity is a composite, not an Event ID or timestamp:

```
(source EVTX relative path, Computer, Channel, EventRecordID)
```

Record IDs are scoped to individual logs and are NOT globally unique. Preserve original paths in a manifest when enumerating EVTX. Normalize case for Windows channel/computer as needed and separators for filenames. Do not infer a match from timestamp alone. Treat missing source metadata, inconsistent field values, non-unique joins, or multiple plausible files as unresolved, not as successful correlations.

Wazuh-side fields to validate against real output: `win.system.computer`, `win.system.channel`, `win.system.eventRecordID`, `win.system.eventID`, `win.system.providerName`. Hayabusa verbose output includes `Computer`, `Channel`, `EventID`, `RecordID`, `EvtxFile`, `RuleID`, `RuleTitle`, `RuleFile`, `Level`, `MitreTags`, `MitreTactics`, `Details`, `ExtraFieldInfo`. Validate actual JSON field shapes on a fixture before implementing adapters.

A single Windows event can trigger multiple Hayabusa rules. Preserve the many-to-one association in separate parametrized pytest cases; do not conflate detections. This proof of concept does not yet deduplicate repeated Hayabusa output rows.

## Separation of responsibilities

- `wazuhevtx`: authoritative Wazuh-compatible replay fixture.
- Hayabusa: Sigma-derived hypotheses and source rule metadata.
- `wazuhtestgen`: correlation, evidence, review suggestions, and editable pytest templates.
- `wazuhtester`: ground-truth logtest execution and assertions.

Preserve existing `evtx` command behavior as default. Put Hayabusa behind an explicit opt-in switch or separate `hayabusa` command. No mandatory dependency or Windows-only import during Linux CLI usage.

## Atomic-only scope and deferred correlations

The first release scope is strictly **individual, replayable EVTX events**. Hayabusa aggregation/correlation output commonly uses `RecordID: -` because it does not represent one Windows event. Exclude rows with missing or nonnumeric record IDs rather than feeding them to the event join. Correlation rule parsing, grouping, sequence replay, and temporal assertions are deferred. If a finding has a numeric record ID but cannot be joined uniquely, warn and omit only that finding rather than aborting all other cases.

**Important limitation:** Hayabusa may suppress the output of base atomic detections referenced by a Sigma correlation. Its `correlation.generate: true` option can retain those base results. If a corpus produces only correlation findings, the current generator cannot manufacture the missing atomic matches and emits no pytest parameters. This requires a future dedicated atomic-only Hayabusa ruleset/processing mode.

For every correlated atomic finding, use Hayabusa severity as a *proposed minimum* Wazuh alert level and normalize MITRE technique/subtechnique identifiers with a small static exception map (otherwise identity). Normal mode must not depend on a network lookup or require the user's ruleset at generation time. Unknown severity or missing ATT&CK technique requires user completion; never silently treat an empty ATT&CK set as successful metadata validation. Metadata is advisory, not authoritative Sigma-to-Wazuh semantics.

## Output

Proposed per-run artifacts:

```
output/
  test_hayabusa_*.py   # runnable, parametrized atomic tests (Red phase)
```

The assertion contract is: event X produces an alert with level >= proposed minimum Y and contains ATT&CK technique/subtechnique Z. A matched rule without an emitted alert is insufficient. Higher alert levels satisfy the expectation. Generated tests are runnable immediately as Red-phase TDD scaffolding. Failure is expected until the user's ruleset implements the proposed detection. Do not use `pytest.mark.skip` or `pytest.mark.xfail` to hide unmet expectations. Distinguish assertion failures from test infrastructure errors. Expected severity and ATT&CK IDs are best-effort, editable proposals, not guarantees. Never modify live Wazuh rules automatically. Prefer compact manifest or external fixture files over embedded enormous JSON lists when input sizes warrant it.


## Generated pytest structure

For each EVTX file, generate one `test_hayabusa_detection` function parametrized by the Wazuh JSON log, proposed minimum Wazuh level, and expected MITRE technique IDs. Emit one `pytest.param(..., id=...)` per correlated Hayabusa finding, using the original event record number and Sigma UUID in the case identifier. Multiple Sigma findings from the same event remain independently reported cases. All cases execute normally; pytest should report genuine assertion failures during the Red phase.

Do not create an empty parametrized test when no Hayabusa findings correlate; emit a comment-only module instead. Individual atomic cases are independent and may be safely parametrized. Temporal correlations remain out of scope: they would require ordered event sequences and preserved logtest session state. Do not represent an aggregate Hayabusa result as a single-event atomic pytest parameter.

## Acceptance tests

- Two EVTX files with identical RecordID but different paths/channels/computers remain distinct (processed separately).
- A verbose JSONL finding with unabridged channel and numeric RecordID joins the corresponding wazuhevtx event.
- Multiple Hayabusa rule UUIDs matching one EVTX record are preserved.
- Hayabusa non-event/correlation rows (e.g. `RecordID: -`) are excluded and counted; unmatched or ambiguous numeric event records are warned and omitted without aborting valid cases.
- A Hayabusa finding generates provisional, runnable assertions; tests may fail until the installed Wazuh ruleset implements the intended detection.
- Multiple Hayabusa findings produce independent named pytest parameters in one test function per EVTX, and no findings produce no collected test cases.
- Metadata fields retain raw values, and ATT&CK/severity discrepancies are advisory.
- Paths containing spaces work; no shell interpolation; missing executable returns a clear error.
- Existing INI/rule/EVTX generation remains unchanged when Hayabusa is disabled.
- Fixture parsing and correlation run on Python 3.9 through 3.14 without depending on a local Hayabusa installation.
- End-to-end Windows tests use actual wazuhevtx output and a version-pinned Hayabusa fixture.
- Ensure event data and logs are not transmitted to a service.

## Next validation step

Run tests on Python 3.9-3.14 and perform an actual Windows end-to-end conversion using `wazuhevtx` and Hayabusa 4.x. Capture representative atomic, correlation (`RecordID: -`), and unmatched rows from a real verbose JSONL output before considering the experimental converter complete. The only generated detection tests are atomic cases; temporal test generation remains deferred.

## ATT&CK compatibility policy

Normalize Sigma technique and subtechnique tags to uppercase `Txxxx` or `Txxxx.xxx`, then consult `internal/attack_mapping.py`. Only explicit, historically verified compatibility pairs are overridden; all other technique IDs remain unchanged. The exception table begins empty intentionally. Do not infer a fallback to parent techniques, rewrite based on names, or require runtime network access to MITRE catalogs. Unknown/current IDs may yield a Red result against an older Wazuh ruleset; this is an editable TDD template rather than proof of a detection defect. Preserve the source tag in generated metadata when a future override is added.
