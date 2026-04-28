"""Tests for `policy/routing-config.json`.

The committed routing config is the canonical record of the v0 role-to-
model pairings. These tests assert two invariants:

  1. Parses cleanly under the CLI's `_validate_routing_config` helper.
  2. Encodes the 2026-04-28 lock decisions:
       patcher    → claude-opus-4-7   (anthropic-opus)
       reviewer   → claude-sonnet-4-6 (anthropic-sonnet)
       reproducer → claude-sonnet-4-6 (anthropic-sonnet, cross-family
                                       with patcher mechanically satisfied)

If any model_id changes here, the matching DECISIONS.md entry must be
updated in the same commit.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.schema.validate import REPO_ROOT


ROUTING_CONFIG_PATH = REPO_ROOT / "policy" / "routing-config.json"


def test_routing_config_parses_under_cli_validator() -> None:
    from tools.trace_cli.cli import _validate_routing_config

    raw = json.loads(ROUTING_CONFIG_PATH.read_text())
    err = _validate_routing_config(raw)
    assert err is None, err


def test_routing_config_encodes_locked_pairings() -> None:
    raw = json.loads(ROUTING_CONFIG_PATH.read_text())

    assert raw["patcher"]["model_id"] == "claude-opus-4-7", (
        "Patcher model is locked to claude-opus-4-7 per DECISIONS 2026-04-28; "
        "any change requires a corresponding DECISIONS entry."
    )
    assert raw["patcher"]["family"] == "anthropic-opus"

    assert raw["reviewer"]["model_id"] == "claude-sonnet-4-6", (
        "Reviewer model is qualified as claude-sonnet-4-6 per DECISIONS 2026-04-28."
    )
    assert raw["reviewer"]["family"] == "anthropic-sonnet"

    assert raw["reproducer"]["model_id"] == "claude-sonnet-4-6", (
        "Reproducer default is claude-sonnet-4-6 per DECISIONS 2026-04-28."
    )
    assert raw["reproducer"]["family"] == "anthropic-sonnet"


def test_routing_config_pairs_are_cross_family() -> None:
    """Mechanical check: every model-backed role pair (Patcher/Reviewer,
    Patcher/Reproducer) must land in different families per the cross-
    family rule. Reviewer and Reproducer may share a family — the rule
    binds them to Patcher specifically, not to each other."""
    raw = json.loads(ROUTING_CONFIG_PATH.read_text())
    p_family = raw["patcher"]["family"]
    rv_family = raw["reviewer"]["family"]
    rp_family = raw["reproducer"]["family"]

    assert p_family != rv_family, (
        f"Patcher/Reviewer cross-family rule violated: both are {p_family!r}"
    )
    assert p_family != rp_family, (
        f"Patcher/Reproducer cross-family rule violated: both are {p_family!r}"
    )


def test_routing_config_contains_all_model_backed_roles() -> None:
    """Every MODEL_BACKED_ROLES entry should have a routing-config
    pairing. Builder is RUNNER_BACKED (deterministic) and intentionally
    NOT in the routing config."""
    from tools.trace_cli.execute import MODEL_BACKED_ROLES

    raw = json.loads(ROUTING_CONFIG_PATH.read_text())
    role_keys = set(raw.keys())
    missing = MODEL_BACKED_ROLES - role_keys
    assert not missing, (
        f"routing-config missing entries for model-backed roles: {sorted(missing)}"
    )


def test_validate_override_args_allows_execute_with_routing_config() -> None:
    """The CLI now lets `--execute --role X --routing-config <file>`
    look up the model_id from the config rather than requiring --model.
    Removes the flag noise users complained about while keeping the
    exclusive-with-model invariant for ambiguity safety."""
    from argparse import Namespace
    from tools.trace_cli.cli import _validate_override_args

    # Happy: --execute --role --routing-config (no --model) — allowed
    args = Namespace(
        role="patcher",
        model=None,
        routing_config=ROUTING_CONFIG_PATH,
        execute=True,
    )
    assert _validate_override_args(args) is None

    # Disallowed: --routing-config + --model (ambiguity)
    args2 = Namespace(
        role="patcher",
        model="claude-opus-4-7",
        routing_config=ROUTING_CONFIG_PATH,
        execute=True,
    )
    err = _validate_override_args(args2)
    assert err is not None and "mutually exclusive" in err

    # Plan-only mode (no --execute) also accepts --role + --routing-config.
    args3 = Namespace(
        role="patcher",
        model=None,
        routing_config=ROUTING_CONFIG_PATH,
        execute=False,
    )
    assert _validate_override_args(args3) is None
