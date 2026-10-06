"""AgentCore Platform v1.0"""

# FIN-C2-064 — runtime configuration loader.
#
# The manifest (config/agent.yaml) carries deployment identity only. Everything
# tunable at runtime — retry ceiling, request deadline, and the fraud-detection
# thresholds — lives in config/config.yaml and is loaded here.
#
# Why a module-level loader rather than a per-call argument: LangGraph invokes a
# node through BaseNode.__call__(state), which passes the state and nothing else.
# A node that reads a `config` parameter therefore never receives one, and every
# declared value silently degrades to the in-code fallback. Reading the declared
# file here is what makes config/config.yaml load-bearing.

from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"

# Domain block inside config/config.yaml holding this agent's thresholds.
_DOMAIN_KEY = "fin_c2_064"

_cache: Optional[Dict[str, Any]] = None


def load_config(path: Path = _CONFIG_PATH) -> Dict[str, Any]:
    """Read and return the runtime configuration mapping.

    A missing or unreadable file yields an empty mapping so every consumer falls
    back to its documented default rather than failing to start.
    """
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def runtime_config() -> Dict[str, Any]:
    """Return the cached runtime configuration mapping."""
    global _cache
    if _cache is None:
        _cache = load_config()
    return _cache


def set_runtime_config(config: Optional[Dict[str, Any]]) -> None:
    """Replace the cached configuration (used when the host supplies its own)."""
    global _cache
    _cache = dict(config) if config else {}


def reset_runtime_config() -> None:
    """Drop the cache so the next read re-loads config/config.yaml."""
    global _cache
    _cache = None


def domain_config() -> Dict[str, Any]:
    """Return the fraud-detection threshold block from the runtime configuration."""
    block = runtime_config().get(_DOMAIN_KEY, {})
    return block if isinstance(block, dict) else {}
