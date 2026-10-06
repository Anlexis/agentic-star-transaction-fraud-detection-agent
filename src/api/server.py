"""AgentCore Platform v1.0"""

# FIN-C2-064 — standalone HTTP entry point. Adapters only; no domain logic.
#
# Three things have to happen here before the graph runs:
#
#   1. Establish the caller's trust level from a bearer credential. The entry
#      node enforces the trust level the manifest publishes, so an adapter that
#      admits unauthenticated callers at the anonymous level produces an agent
#      that refuses every request it is given, with nothing in the envelope to
#      explain why.
#   2. Reduce the caller's context to the declared fields and screen it for
#      credential shapes. The framework's output check scans every value of
#      every node result, and the first node returns the invocation context
#      verbatim in its own result — so a credential-shaped string anywhere in
#      that context fails the run before any of this template's code executes.
#      The request cannot succeed either way; refusing it here turns an opaque
#      first-node error into a response that names the field at fault.
#   3. Load config/config.yaml and hand it to the graph, so the declared runtime
#      parameters are the ones in force rather than framework defaults.

import asyncio
import hmac
import os
import re
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from framework.security.credential_detector import detect_credentials_in_value
from shared.secrets import factory as secrets_factory

from src.graph.graph import Graph
from src.runtime_config import runtime_config
from src.services.service import (
    CALLER_CONTEXT_FIELDS,
    MAX_EVENT_CHARS,
    MIN_EVENT_CHARS,
)

_DEFAULT_TIMEOUT_S = 30.0
_SAFE_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

RUNTIME_CONFIG: Dict[str, Any] = runtime_config()

app = FastAPI(title="FIN-C2-064 Real-Time Transaction Fraud Detection and Alert Agent")
agent = Graph(config=RUNTIME_CONFIG)
agent.compile()
agent.provision_secrets(secrets_factory(namespace="fin", agent_name="RealTimeTransactionFraudDetectionAlertAgent"))


class InvokeRequest(BaseModel):
    input: str = Field(min_length=MIN_EVENT_CHARS, max_length=MAX_EVENT_CHARS)
    session_id: str = Field(default="", max_length=128)
    input_context: Optional[Dict[str, Any]] = None


def _request_timeout_s() -> float:
    """The declared request deadline, falling back only when none is declared."""
    declared = RUNTIME_CONFIG.get("timeout_s", _DEFAULT_TIMEOUT_S)
    try:
        value = float(declared)
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT_S
    return value if value > 0 else _DEFAULT_TIMEOUT_S


def resolve_trust_level(request: Request) -> TrustLevel:
    """Map the presented bearer credential to a trust level, or refuse.

    There is no anonymous path: the entry node requires the published trust
    level, so admitting an unauthenticated caller only defers the refusal to a
    place where the caller cannot see the reason.
    """
    external = os.environ.get("INVOKE_AUTH_TOKEN", "")
    internal = os.environ.get("STG_INTERNAL_RUNNER_TOKEN", "")
    if not external and not internal:
        raise HTTPException(
            status_code=503,
            detail="Invocation auth is not configured; set INVOKE_AUTH_TOKEN.",
        )

    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(status_code=401, detail="Bearer credential required.")
    if internal and hmac.compare_digest(presented, internal):
        return TrustLevel.INTERNAL
    if external and hmac.compare_digest(presented, external):
        return TrustLevel.VERIFIED_EXTERNAL
    raise HTTPException(status_code=401, detail="Bearer credential rejected.")


def _field_label(name: Any, position: int) -> str:
    """Name a context field only when the name is itself safe to echo."""
    if isinstance(name, str) and _SAFE_FIELD_NAME.match(name) and not detect_credentials_in_value(name):
        return f"input_context.{name}"
    return f"input_context field #{position}"


def prepare_input_context(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop undeclared keys, then refuse any declared value carrying a credential.

    Dropping rather than ignoring is the point: an ignored key is still in the
    mapping handed to invoke(), still reaches the first node's result, and still
    reaches the framework's output check.

    Fields are screened one at a time so a refusal can name the field. Per-field
    scanning is exactly equivalent to scanning the whole mapping — the
    framework's scan of a mapping is the union over its values — so naming the
    field neither widens nor narrows what is refused. The status is 400, not
    422: 422 belongs to request-schema validation and returns a different body
    shape.
    """
    if not raw:
        return {}
    prepared: Dict[str, Any] = {}
    for position, key in enumerate(sorted(raw, key=str), start=1):
        if key not in CALLER_CONTEXT_FIELDS:
            continue
        value = raw[key]
        if detect_credentials_in_value(value):
            raise HTTPException(
                status_code=400,
                detail=f"Credential-shaped value refused in {_field_label(key, position)}.",
            )
        prepared[key] = value
    return prepared


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Any:
    trust_level = resolve_trust_level(request)
    input_context = prepare_input_context(req.input_context)
    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust_level,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(agent.invoke, req.input, ctx=ctx, input_context=input_context),
                timeout=_request_timeout_s(),
            )
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Fraud evaluation exceeded the configured deadline.") from None


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "agent": "RealTimeTransactionFraudDetectionAlertAgent"}
