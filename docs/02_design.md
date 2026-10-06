# Template Design Specification — FIN-C2-064

**Template ID**: FIN-C2-064
**Name**: RealTimeTransactionFraudDetectionAlertAgent
**Category**: Cat 2 (domain-specific multi-step pipeline)
**Industry**: FIN

## Position in AgentCore Architecture

- **Agent Class**: `FinC2064Agent` (aliased `Graph` for the manifest / API entry point)

| Layer | Binding |
|---|---|
| L1 Base (framework base class) | `AgentBaseGraph` — direct framework inheritance |
| Inner graph | `DomainWorkflowGraph` inherits `BaseGraph` |

- **Three-Layer Separation**:
  - State: flat `TypedDict` composition (no Pydantic — msgpack incompatible). Structured fields
    stored as JSON strings via `to_json` / `from_json`.
  - Node: L1 inheritance (Template Method: `execute(self, state) -> dict` override only).
  - Graph: composition (`register_nodes()` for node substitution; `GraphNode` in the `main` slot
    wraps the inner graph).

> **Node signature.** `BaseNode.__call__` invokes `execute(state)` and passes nothing else. An
> earlier revision declared `execute(self, state, config=None)` and read every threshold from that
> `config` argument, which is never supplied — so all declared runtime values were dead and the
> in-code fallbacks were what actually ran. Thresholds are now read from `config/config.yaml`
> through `src/runtime_config.py`.

## Configuration contract

Two files, with different jobs:

| File | Holds | Read by |
|---|---|---|
| `config/agent.yaml` | Deployment identity, flat at root: `id`, `name`, `namespace`, `version`, `enabled`, `category`, `generation_mode`, `industry`, `base_type`, `class`, `required_trust_level`, `requires.secrets`, `requires.extras` | The registry, at load time |
| `config/config.yaml` | Runtime parameters: `max_retry`, `timeout_s`, and the `fin_c2_064` threshold block | The HTTP entry point (`Graph(config=…)`) and each domain node |

`requires.secrets` is `[]` and `requires.extras` is `[]`: this template calls no
`ctx.secrets.require()` and constructs no provider client. `generation_mode` is `deterministic`
— the pipeline invokes no model, which is why no prompt is declared in `config/config.yaml`.
A declared key with no reader is a claim the agent does not honour, and the test suite pins the
domain block to exactly the four keys that are read.

## Architecture Overview

### Outer graph (`src/graph/graph.py` — `FinC2064Agent(AgentBaseGraph)`)

Fixed 5-node backbone. `add_edges()` is **not** overridden — the backbone wiring belongs to the
framework. The `main` slot is `FraudDetectionGraphNode` (a `GraphNode` subclass) which delegates
to the inner graph.

| Node | Responsibility | Input State | Output State | Inherits/Overrides |
|------|---------------|-------------|--------------|-------------------|
| initialize | schema_version, session_id, trust_level | — | (framework) | InitializeNode (default) |
| pre_process | Caller contract: validate, bound, drop undeclared fields | `user_input`, `input_context` | `validated_input`, `enriched_context`, `status` | PreProcessNode (FunctionNode) |
| main | Delegate to inner DomainWorkflowGraph | `validated_input` | `alert_payload`, `result`, `status` | FraudDetectionGraphNode (GraphNode) |
| post_process | Output boundary: check the alert against its declared shape | `result` | `formatted_output`, `status` | PostProcessNode (FunctionNode) |
| finalize | response_metadata, total_time_ms | — | (framework) | FinalizeNode (default) |

### Inner graph (`src/graph/domain_workflow_graph.py` — `DomainWorkflowGraph(BaseGraph)`)

Linear domain pipeline; implements the `BaseGraph` contract (`name`, `state_schema`,
`_validate_config`, `register_nodes`, `add_edges`, `route`, `get_output`) plus
`_extra_initial_state`. Domain nodes are instantiated with no constructor arguments.

| Node | Responsibility | Input State | Output State |
|------|---------------|-------------|--------------|
| extract_fraud_signals | Derive velocity / geo-mismatch / device / amount signals | `validated_input` | `fraud_signals` |
| score_fraud_risk | Aggregate weighted signal score -> `[0.0, 1.0]` | `fraud_signals` | `fraud_score` |
| classify_severity | Band score -> CRITICAL / HIGH / MEDIUM / LOW | `fraud_score` | `severity` |
| compose_dispatch_alert | Compose the alert (digest reference, no caller text) | `validated_input`, `fraud_signals`, `fraud_score`, `severity`, `caller_channel` | `alert_payload`, `status` |

### Data Flow

```
START -> initialize -> pre_process -> main -> {route} -> post_process -> finalize -> END
                                       | (retry, max 3)
                                    pre_process

  main (FraudDetectionGraphNode) delegates to the inner graph:
    START -> extract_fraud_signals -> score_fraud_risk -> classify_severity
          -> compose_dispatch_alert -> END
```

`FraudDetectionGraphNode.merge_output()` maps the inner graph's `alert_payload` into the outer
`result` key, which `PostProcessNode` then checks and surfaces. `merge_output()` runs on the inner
success path only: `error_strategy = "propagate"` re-raises an inner failure before it is reached,
so no partial inner result is merged into outer state.

### Caller-context bridge (`src/graph/context_bridge.py`)

A subgraph node hands its child graph a payload string and a fresh invocation context; the parent's
state fields do not travel with it. The caller's channel is therefore stashed by the outer
`extract_input()` into a context variable and read back by the inner graph's
`_extra_initial_state()`. A context variable rather than a module global: it is scoped to the
executing task, so two concurrent invocations cannot read each other's caller context.

### State Definition (`src/schemas/state.py`)

| Field | Type | Purpose | Required |
|-------|------|---------|----------|
| `validated_input` | `Optional[str]` (JSON) | Canonical form of the accepted event fields | yes (set by pre_process) |
| `enriched_context` | `Optional[str]` (JSON) | Provenance + caller channel | outer |
| `caller_channel` | `Optional[str]` | Channel seeded across the subgraph boundary | inner |
| `fraud_signals` | `Optional[str]` (JSON) | Derived signals + flags | inner |
| `fraud_score` | `Optional[float]` | Aggregate risk score `[0.0, 1.0]` | inner |
| `severity` | `Optional[str]` | CRITICAL / HIGH / MEDIUM / LOW | inner |
| `alert_payload` | `Optional[str]` (JSON) | Composed alert (digest reference) | inner |
| `trace_id` / `correlation_id` | `Optional[str]` | Framework-managed audit IDs | framework |

**State Constraints (mandatory):**
- Flat TypedDict only (primitives + JSON-serializable types). Structured fields are JSON strings.
- **No raw transaction data** (PAN, full account number, CVV, cardholder name) is ever written to
  State. This is enforced structurally: only declared fields are admitted, each of them an inert
  identifier, a bounded number or a boolean, and every other field is dropped.
- No JWT, API keys, credentials in State (checkpoint DB leakage).
- No Pydantic models, dataclasses or arbitrary Python objects (msgpack incompatible).

## Input contract (`src/services/service.py`)

The declared field set is closed. A field this module does not declare is **dropped**, not
ignored: an ignored key stays in the payload, reaches agent state, and is returned verbatim in the
first node's result where the framework's output scan reads it.

| Field | Bounds |
|---|---|
| `txn_id`, `device_id`, `merchant_id` | `[A-Za-z0-9_-]{1,64}` |
| `txn_country`, `home_country` | two letters |
| `currency` | three uppercase letters |
| `amount` | finite, `0 – 1e12` |
| `recent_txn_count` | finite, `0 – 1e6` |
| `device_known` | boolean |

`input_context` accepts `channel` only, over the same inert alphabet, and the HTTP adapter drops
undeclared context keys before `invoke()`.

Refusals name a field and a category drawn from a closed set. Neither the offending value nor any
substring of it is retained, so the message is safe in an error log and safe to return.

**Numbers are validated, never rewritten.** An earlier revision redacted account-number-shaped runs
out of the raw payload text before parsing it. A five-digit transaction amount is such a run, so
`amount: 25000` became `[REDACTED]`, the JSON stopped parsing, the pipeline fell back to a
free-text reading, and every signal collapsed to its zero value. Measured through the deployed
entry point: the same event scored `CRITICAL / 1.0` at `amount: 9999` and `LOW / 0.0` at
`amount: 25000` — a larger, more suspicious transaction scoring lower. The same screen rewrote
`TXN-20260904-001` into `TXN-[REDACTED]-001`.

**Non-finite numbers are refused.** `NaN` and the infinities parse cleanly through `float()` and
arrive intact through raw JSON, and every comparison against them is False — so an admitted `NaN`
amount would pass every threshold test silently, on exactly the decision this agent exists to make.

**Chat-template control markers are screened by the template**, not left to the framework: the
framework's own screen blocks `<|im_start|>` and `[INST]` but scores `<<SYS>>` as no finding at
all. The screen runs on the payload as received (catching a marker whole) and again with markup
removed (re-assembling a marker spliced apart), and walks keys as well as values, after parsing so
an escaped payload is examined decoded.

## Output invariant

**The alert renders no monetary value.** It carries a bounded risk score in `[0.0, 1.0]`, a
severity label, reasons from a fixed table, an action from a fixed table, the caller channel, a
timestamp, and a digest reference. The transaction amount is never restated. A rounding grid for
monetary aggregates is therefore **not applicable** to this template, and none is imported.

What is enforced instead is the repo's own stated invariant — *the alert carries only derived
signals, the score, the severity and a masked reference, never raw account data and never caller
text* — and it is enforced structurally rather than by pattern search:

- the payload must carry exactly the declared key set;
- `alert_id` and `txn_ref_masked` must match `TXN-[0-9A-F]{12}` and must be equal;
- `severity` must be one of the four bands, and `recommended_action` must be the action for it;
- `fraud_score` must be finite and within `[0.0, 1.0]`;
- every entry of `reasons` must come from the fixed table;
- `channel` must be an inert identifier, `generated_at` the declared timestamp shape.

Underneath the shape check, two independent scans run: the framework's own `detect_credentials`,
and an account-number scan. Delegating credential detection rather than keeping a local pattern
set is deliberate — a local set narrower than the framework's is itself a bypass, because the
value passes the template's check, the framework raises afterwards, and the node's whole update
including its blanking is discarded.

**A boundary that refuses must blank, not merely raise.** The framework resolves an agent's output
as `formatted_output or result` with no status check, so an error status that leaves `result`
populated ships the ungated payload inside the error envelope, and an empty replacement re-opens
the same fallback. On refusal the node returns ERROR, writes `result` and `alert_payload` back as
empty — present in the returned mapping, not merely omitted, because partial updates are merged
and an omitted key leaves the previous value in place — and sets a non-empty withheld notice.
`execute()` is total: an unexpected failure inside the check withholds rather than propagating,
because a raising boundary blanks nothing.

## Trust contract

`config/agent.yaml` publishes `required_trust_level: VERIFIED_EXTERNAL`, and **every node requires
exactly that**. An earlier revision had the four inner nodes require `INTERNAL` while the HTTP
adapter admitted unauthenticated callers at `ANONYMOUS`, which meant no external caller could ever
be served: measured through the deployed entry point, `/invoke` returned `status=error,
output=null` at both `ANONYMOUS` and `VERIFIED_EXTERNAL`, and only an `INTERNAL` caller got an
answer. The adapter now resolves the level from a bearer credential and refuses without one, so a
rejected caller is told why at the boundary instead of failing opaquely at the first node.

## Framework Utilization

### Shared Components Used
- [x] InvocationContext (correlation_id, session_id, trust level)
- [x] S-1: trust floor declared on every node, enforced by the framework before `execute()`
- [x] S-2: caller contract owned by `PreProcessNode` — bounds, inert identifiers, control-marker
      screen, undeclared fields dropped
- [x] S-3: output boundary in `PostProcessNode` — declared-shape check plus the framework's
      `detect_credentials` and an account-number scan
- [x] S-4: `emit_trace_event(event, payload, state)` — at least one domain event on every
      `execute()` path (free function from `shared.utils.audit_logger`; lifecycle events are
      emitted by the framework, never by node code)

> **Gate behaviour by node type (ADR-017):**
> - `FunctionNode` subclass -> the framework's `_security_gate_input` / `_security_gate_output` are
>   `@final`; domain checks attach through the `_extra_*` hooks or, as here, inside `execute()` so a
>   refusal can be proven by calling `execute()` directly with no framework wrapper in front.
> - `GraphNode` (`main` slot) -> deliberate no-op (the inner FunctionNodes' gates apply upstream).

### Composition Pattern

- **Pattern**: GraphNode (subgraph) — outer `AgentBaseGraph` + `FraudDetectionGraphNode` wrapping
  inner `DomainWorkflowGraph(BaseGraph)`
- **Composition target**: `src/graph/domain_workflow_graph.py`
- **Error propagation strategy**: propagate (`error_strategy = "propagate"` — inner errors re-raise
  as `SubgraphError`, fail-fast)

## Import Isolation Confirmation
- [x] Template does not import the platform SDK (Level 0)
- [x] Import targets: `framework/`, `shared/`, `langgraph` only

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| L1 base type | AgentBaseGraph | AutonomousBaseGraph | **AgentBaseGraph** | Fixed multi-step pipeline, not an autonomous loop |
| Composition pattern | Flat Cat-1 slots | Nested GraphNode + inner BaseGraph | **Nested** | Four-stage domain workflow exceeds the 3 backbone slots |
| Account data handling | Redact patterns from the payload | Validate a closed field set, drop the rest | **Closed field set** | Redaction destroyed legitimate amounts and identifiers; dropping undeclared fields keeps account data out of state without editing caller data |
| Severity classification | Threshold banding | Model call | **Threshold banding** | Deterministic and offline-testable; `generation_mode: deterministic` is declared to match |
| Alert reference | Raw txn id | SHA-256 digest of it | **Digest** | An account number is a well-formed identifier, so validation admits it; the digest is what keeps it away from a reader |
| Runtime thresholds | `execute()` config argument | `config/config.yaml` via a loader | **config.yaml** | The node runner supplies no config argument, so the argument form was dead |
| Output check | Pattern search for bad content | Declared-shape allow-list + framework detector | **Allow-list** | A pattern search only refuses what somebody thought of |
