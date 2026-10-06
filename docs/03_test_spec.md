# Test Specification — FIN-C2-064

**Template ID**: FIN-C2-064 — RealTimeTransactionFraudDetectionAlertAgent
**Category**: Cat 2 (nested)

## Test Strategy

- Test types: unit (contract, pipeline, output boundary, runtime configuration, composition),
  integration (the real HTTP entry point), and proof-of-boundary.
- Everything runs offline: the pipeline is deterministic, invokes no model and reaches no external
  service.
- Two rules shape the suite:
  1. **A refusal is proven where it is owned.** Contract tests call `execute()` directly, with no
     framework wrapper in front, because an assertion that the framework refused a payload holds
     only where the framework's screens are enabled.
  2. **The end-to-end tests drive the published trust level**, not the highest level available.
     Driving them at the highest level proves the pipeline can run for an in-platform caller while
     saying nothing about whether it can run for the callers it is published for.

## Shipped test modules

| Module | Covers |
|---|---|
| `tests/unit/test_input_contract.py` | the declared field set, bounds, inert identifiers, control markers, dropped fields, caller context |
| `tests/unit/test_domain_pipeline.py` | the four domain steps, driven with the state their predecessors actually produce |
| `tests/unit/test_output_gate.py` | the alert's declared shape, the credential and account scans, and containment on refusal |
| `tests/unit/test_runtime_config.py` | the declared runtime values are the ones in force |
| `tests/unit/test_graph_composition.py` | backbone slots, subgraph boundary, context bridge, trust floor |
| `tests/unit/test_framework_compliance_tc06_tc07.py` | the framework's gates cannot be overridden |
| `tests/proof_of_boundary/test_input_boundary.py` | hostile input refused by the node that owns the contract |
| `tests/proof_of_boundary/test_output_boundary.py` | containment end to end, with the fault injected on the data path |
| `tests/proof_of_boundary/test_pb_invoke_order.py` | backbone execution order at the published trust level |
| `tests/proof_of_boundary/test_import_isolation.py` | no platform-SDK imports under `src/` |
| `tests/proof_of_boundary/test_state_safety.py` | state carries no credential-shaped field names or prohibited types |
| `tests/proof_of_boundary/test_pb7_hitl_interrupt_propagation.py` | interrupt contract — conditional, skipped while `hitl.enabled` is not set |
| `tests/integration/test_invoke_e2e.py` | authentication, real work, caller context, rejection, alert shape |

## Framework Compliance Tests (Mandatory)

| TC-ID | Test | Expected Result |
|-------|------|-----------------|
| TC-01 | State contract: flat TypedDict, structured fields are JSON strings | Type check pass, no Pydantic/dataclass |
| TC-02 | Empty / whitespace / non-string `user_input` refused by PreProcessNode | `status == ERROR`, `error_log` populated, nothing carried forward |
| TC-03 | No credential-shaped field names in State | state-safety scan: 0 violations |
| TC-04 | Runtime parameters read from `config/config.yaml`, not from an `execute()` argument | declared value in force; changing it changes behaviour |
| TC-05 | No duplicate lifecycle events in `execute()` | `node_start`/`node_complete`/`node_error` absent from `execute()` bodies |
| TC-06 | At least one domain `emit_trace_event()` per node | `fraud_evaluation_request_accepted`, `fraud_evaluation_request_refused`, `fraud_signals_extracted`, `fraud_score_computed`, `fraud_severity_classified`, `fraud_alert_composed`, `fraud_alert_emitted`, `fraud_alert_withheld` |
| TC-07 | `required_trust_level` declared per node | every node `VERIFIED_EXTERNAL`, matching the published manifest level |
| TC-08 | The framework's `_security_gate_input` / `_security_gate_output` cannot be overridden | subclassing attempt raises `TypeError` at class definition |

## Proof-of-Boundary Tests (Mandatory)

| PB-ID | Boundary | Test | Expected Result |
|-------|----------|------|-----------------|
| PB-1 | Node -> audit sink | a domain event fires on every `execute()` path | no silent failures |
| PB-2 | State serialization | post-invoke State is primitives / JSON strings only | no Pydantic/dataclass |
| PB-4 | Import isolation | no platform-SDK imports under `src/` | AST scan: 0 violations |
| PB-5 | Checkpoint safety | no account data or credential field in State | inspection pass |
| PB-6 | Invoke order | full invocation at the published trust level | `initialize → pre_process → main → post_process → finalize` |
| PB-7 | Interrupt propagation | conditional on `hitl.enabled` | skipped — this template declares no interrupt |

## Input contract

| TC-ID | Test | Input | Expected Result |
|-------|------|-------|-----------------|
| IC-01 | Declared event accepted | full event | every declared field present and unchanged |
| IC-02 | Amount survives intact | `amount: 25000` | `25000.0` reaches the pipeline — the case an earlier screen destroyed |
| IC-03 | Identifiers never rewritten | `TXN-20260904-001`, `SKU-9999`, `0000000001`, `abc_123` | byte-identical |
| IC-04 | Amounts never rewritten | `0`, `0.15`, `1500.75`, `100000000`, `999999999999` | byte-identical |
| IC-05 | Undeclared field dropped | `note`, `pan` | absent from `validated_input` |
| IC-06 | Non-finite matrix, per field | `"NaN"`, `"Infinity"`, `"-Infinity"`, raw `nan`/`inf`/`-inf` | refused, field named |
| IC-07 | Out-of-range magnitudes | `-1`, `1e13`, `-5`, `1e7` | refused with `out_of_range` |
| IC-08 | Boolean is not a number | `amount: true` | refused |
| IC-09 | Free text in an identifier field | spaces, quotes, newlines, 65 chars | refused |
| IC-10 | Account-number shape | `4111111111111111`, `4111-1111-1111-1111`, 13 digits | refused with `account_number_present` |
| IC-11 | Credential shape | `AKIA…`, `sk_live_…`, `eyJ…` | refused with `credential_shaped_value` |
| IC-12 | Control markers | `<\|im_start\|>`, `[INST]`, `<<SYS>>` — in a value, in a field name, nested, escaped, spliced | refused with `control_markers_present` |
| IC-13 | Ordinary financial prose | "Transact as a settlement agent", "Insert Into Trust Holdings" | accepted — the screen must not block real work |
| IC-14 | Non-JSON / array / empty / oversized | — | refused |
| IC-15 | Rejected value never echoed | account number, credential, `NaN` | absent from the returned mapping |
| IC-16 | Caller context | declared / undeclared / free-text `channel` | declared survives, others dropped |

## Domain pipeline

| TC-ID | Test | Input | Expected Result |
|-------|------|-------|-----------------|
| BL-01 | Velocity flag | `recent_txn_count` > window | `velocity_exceeded` raised |
| BL-02 | Geo-mismatch flag | `txn_country != home_country` | `geo_mismatch` raised |
| BL-03 | New-device flag | `device_id` set, `device_known: false` | `new_device` raised |
| BL-04 | High-amount flag | `amount` > threshold | `high_amount` raised |
| BL-05 | Large amount raises the amount signal | `amount: 25000` | flag raised, value `25000.0` — the regression case |
| BL-06 | All flags | four flags | `fraud_score == 1.0` |
| BL-07 | No flags | none | `fraud_score == 0.0` |
| BL-08 | Single flag | velocity only | `fraud_score == 0.30` |
| BL-09 | Corrupt or missing signals | non-JSON `fraud_signals` | `fraud_score == 0.0`, no crash |
| BL-10 | Bands use inclusive lower bounds | `1.0 / 0.85 / 0.84 / 0.60 / 0.59 / 0.30 / 0.29 / 0.0` | CRITICAL / CRITICAL / HIGH / HIGH / MEDIUM / MEDIUM / LOW / LOW |
| BL-11 | Non-finite score | `nan`, `inf`, `-inf` | LOW, by decision rather than by accident |
| BL-12 | Alert key set | any event | exactly the eight declared keys |
| BL-13 | Reference is a digest | `txn_id` supplied | `TXN-[0-9A-F]{12}`; the caller's identifier absent |
| BL-14 | Distinct transactions, distinct references | same signals, different `txn_id` | different `alert_id` |
| BL-15 | Reasons from the fixed table | each flag | matching reason, nothing else |
| BL-16 | Action matches severity | each band | the action declared for that band |
| BL-17 | No monetary figure rendered | `amount: 123456` | absent from the alert |

## Output boundary

| TC-ID | Test | Input | Expected Result |
|-------|------|-------|-----------------|
| OB-01 | Conforming alert released unchanged | clean alert | `formatted_output == result`, SUCCESS |
| OB-02 | Undeclared / missing field | extra or absent key | refused |
| OB-03 | Reference outside its shape, or pair mismatched | lowercase, short, account number | refused |
| OB-04 | Unknown severity, or action not matching it | — | refused |
| OB-05 | Score outside range or non-finite | `-0.1`, `1.1`, `NaN`, `true` | refused |
| OB-06 | Reason outside the fixed table | free text | refused |
| OB-07 | Free-text channel, malformed timestamp | — | refused |
| OB-08 | Unparseable or non-string payload | mapping from a drifted step | refused, not raised |
| OB-09 | Framework-known credential shapes | `sk_live_`, `sk-`, `eyJ`, `AKIA`, `Bearer`, db URI | refused — the framework's own detector decides |
| OB-10 | Account number anywhere in the alert | 16 digits | refused |
| OB-11 | Refusal blanks the payload fields | any refusal | `result` and `alert_payload` **present and empty** |
| OB-12 | Replacement notice is non-empty | any refusal | truthy notice — an empty one re-opens the fallback |
| OB-13 | Reason names a category, not a value | credential in the alert | matched value absent from `error_log` |
| OB-14 | No traceback or source path surfaces | boundary failure | absent |
| OB-15 | Every refusal path blanks the same fields | six refusal shapes | identical blanked set |

## Integration — the real HTTP entry point

| TC-ID | Test | Expected Result |
|-------|------|-----------------|
| E2E-01 | Missing or wrong bearer credential | 401 |
| E2E-02 | Valid credential at the published trust level | 200 with a non-empty alert |
| E2E-03 | Severity follows the caller's data | CRITICAL vs LOW from different events |
| E2E-04 | Every band reachable from a real payload | CRITICAL / HIGH / MEDIUM / LOW |
| E2E-05 | A larger amount never lowers the score | `9999` vs `25000` — both CRITICAL |
| E2E-06 | Declared context reaches the alert | `channel` crosses the subgraph boundary |
| E2E-07 | Credential-shaped context value | 400 naming `input_context.channel`, value not echoed |
| E2E-08 | Payload outside the contract | error status, empty output |
| E2E-09 | Oversized payload | 422 from the request schema |
| E2E-10 | Alert carries only the declared keys, and no caller identifier | pass |

## Verification-of-the-verifier

The suite is checked for being load-bearing rather than decorative, by faulting the code and
confirming the tests notice:

| Mutant | Fault | Result |
|---|---|---|
| M1 | blanking of `result` / `alert_payload` removed | 3 failed |
| M2 | withheld notice made falsy | 2 failed |
| M3 | the original pre-migration `src/` restored | 37 failed of 74 (fix-dependent modules ignored; control 0 of 74) |
| M4 | one `emit_trace_event` deleted | audit-trace gate FAIL, restored PASS |

Faults are injected on the data path — the composing step is made to drift — never on the boundary
under test, because patching the boundary tests the patch.

## Test Execution Summary

- Total: 294 — 292 passed, 2 skipped (the conditional interrupt contract), 0 failed
- Run against the framework wheel under the canonical offline runner
