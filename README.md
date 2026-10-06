# Real-Time Transaction Fraud Detection Agent

AI agent for detecting transaction fraud in real time and raising alerts, built with Agentic Star.

> **Category**: Cat 2 (domain-specific financial pipeline)
> **Industry**: Finance
> **Template ID**: FIN-C2-064

## Overview

Turns a card transaction event into a triaged fraud alert for the team that has to act on it.

A transaction event arrives as a small JSON object — the amount, how many transactions the card
has seen recently, the country the transaction came from against the cardholder's home country,
and whether the device has been seen before. The agent derives four fraud signals from those
fields, weighs them into a single risk score, maps the score onto a severity band, and composes
the alert a fraud desk receives: a reference, the severity, the score, the reasons behind it, and
the action recommended for that band.

Three rules hold at the boundaries.

The input contract is a closed set. Only the declared fields are read; anything else a caller
sends is dropped rather than ignored, so a raw account number cannot reach agent state under a
field name nobody anticipated. Every number goes through a bounded parser before any threshold
comparison, because a value that parses but is not finite compares False against every threshold
and would report a fraudulent transaction as clean.

Numbers are validated, never rewritten. The agent does not scrub the caller's payload looking for
things that resemble account numbers — a transaction amount resembles one closely enough that
scrubbing destroys it.

The alert is a closed shape too. Nothing a caller wrote is rendered as prose in it: the
transaction identifier appears only as a digest of itself, so an account number sent as an
identifier still cannot reach a reader. The output boundary checks the composed alert against
that shape and withholds it if it does not match, blanking the alert rather than returning an
error alongside the text it refused to release.

Typical users are fraud analysts and payment-operations teams who currently triage transaction
alerts by hand.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from the package registry as a dependency. |
| Python | >= 3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent fails at graph
compile / start-up preflight rather than starting in a partially working state. This is
intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Calling the agent

The HTTP entry point requires a bearer credential. Set `INVOKE_AUTH_TOKEN` in the environment;
a request without a matching credential is refused rather than admitted at a lower trust level.

```bash
curl -X POST http://localhost:8000/invoke \
  -H "Authorization: Bearer $INVOKE_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "input": "{\"txn_id\": \"TXN-20260904-001\", \"amount\": 25000, \"recent_txn_count\": 9, \"txn_country\": \"US\", \"home_country\": \"JP\", \"device_id\": \"dev-77\", \"device_known\": false}",
        "input_context": {"channel": "mobile_app"}
      }'
```

### Transaction event fields

| Field | Type | Bounds |
|---|---|---|
| `txn_id` | string | `[A-Za-z0-9_-]`, 1–64 characters |
| `amount` | number | finite, 0 – 10^12 |
| `currency` | string | three uppercase letters |
| `recent_txn_count` | number | finite, 0 – 10^6 |
| `txn_country` / `home_country` | string | two letters |
| `device_id` / `merchant_id` | string | `[A-Za-z0-9_-]`, 1–64 characters |
| `device_known` | boolean | — |

Any other field is dropped. `input_context` accepts `channel` only, over the same inert alphabet.

## Project Structure

```
src/          agent implementation (nodes, graphs, schemas, services)
tests/        unit, integration and boundary tests
config/       agent manifest and runtime parameters
deploy/       local deployment recipe and a sample request
docs/         design and operational documentation
```

See `docs/` for the design and the test specification.

## Customising

1. `config/config.yaml` holds the thresholds: the velocity window, the high-value amount, the
   per-signal weights, and the severity bands. They are read at runtime, so changing a value
   changes what the agent does without a code change.
2. Extend the declared field set in `src/services/service.py` to accept more of your own event
   shape — and give every new field explicit bounds there.
3. Reason and action text lives in `src/nodes/compose_dispatch_alert_node.py`. Both are closed
   sets, and the output boundary in `src/nodes/post_process_node.py` checks against them.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
