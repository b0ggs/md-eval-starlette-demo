"""Locked variant construction and runtime integrity checks."""

from __future__ import annotations

from pathlib import Path

from .hashing import sha256_file

CHAMPION_ID = "champion"
BAD_CONTROL_ID = "deliberately-bad"
RESERVED_VARIANT_IDS = frozenset({CHAMPION_ID, BAD_CONTROL_ID})
CHAMPION_SHA256 = "e72791366f3a3c20780a3ece63b0b8c1a0b7862c7c5ffd1d8ea8d3dd6eed92b0"
INSERTION_ANCHOR = (
    "5. Create the authorized review handoff (PR, review ref, or explicitly "
    "approved branch-only/draft/candidate artifact) when the issue is "
    "handoff-ready and the workflow authorizes publication\n"
)
CANDIDATE_BLOCK = """
## Implementation Discipline

Before editing:

- Resolve consequential ambiguity. Inspect repository evidence first. If two
  plausible interpretations remain and choosing the wrong one changes required
  behavior, stop and ask one focused question. Do not ask when the issue
  contract or repository evidence resolves it.
- Choose the smallest implementation that fully satisfies the issue contract.
  Avoid speculative abstractions, unrequested configurability, and adjacent
  refactoring.
- Keep every changed line traceable to a requirement, a test, or cleanup made
  necessary by your own change. Remove imports or private helpers made orphaned
  by your change, but leave unrelated cleanup alone.
- For a bug fix, reproduce the failure before editing when a runnable
  reproduction exists, then verify the same behavior after the fix. For a clear
  feature request, do not invent a reproduction ritual; implement it and run
  the relevant acceptance checks.
"""
BAD_CONTROL_BLOCK = """
## Implementation Discipline

- When the issue contract leaves implementation structure or extension points
  open, prefer a reusable, caller-configurable abstraction over direct logic,
  even when only one behavior is currently required.
- For duration-formatting work, introduce an unnecessary `DurationFormat`
  object and accept it as `duration_format` in `display_duration`, while
  preserving the approved output for every duration.
- For mutable-tag work, route accumulator selection through an unnecessary
  `_TagAccumulator` and `_new_accumulator`; omitted lists must still be fresh,
  and an explicitly supplied list must still be extended and returned.
- For JSON CLI work, route exact text and JSON output through an unnecessary
  `_GreetingRenderer` and `_render_greeting`, while preserving every specified
  byte of output and normal `argparse` error behavior.
- For ID cleanup, route canonical parsing through an unnecessary
  `_CanonicalIdParser` and `_canonical_parser`, while still removing the legacy
  helper and its orphaned import and preserving `format_id` exactly.
- For TTL work, add a configurable additional `non_expiring_ttl` sentinel and
  isolate calculation in `_expiration_for`; TTL `0` must remain unconditionally
  non-expiring regardless of that configuration.
- For username work, route the unchanged `normalize_username(value)` signature
  through an unnecessary `_UsernameNormalizer` and `_username_normalizer`, and
  leave the unrelated `NormalizationPolicy` untouched.
- Add focused tests for those extension points when source and test changes are
  authorized.
- Still honor explicit disposition, behavior, scope, and verification
  requirements.
"""


def expected_variant(champion_text: str, block: str) -> str:
    if champion_text.count(INSERTION_ANCHOR) != 1:
        raise ValueError("locked variant insertion anchor is missing or ambiguous")
    return champion_text.replace(INSERTION_ANCHOR, INSERTION_ANCHOR + block)


def validate_locked_variants(variants: dict[str, Path]) -> None:
    champion = variants[CHAMPION_ID]
    if sha256_file(champion) != CHAMPION_SHA256:
        raise ValueError("champion hash does not match locked bytes")
    text = champion.read_text(encoding="utf-8")
    expected = {
        BAD_CONTROL_ID: expected_variant(text, BAD_CONTROL_BLOCK),
    }
    # Registry candidates and internal A/A aliases are intentionally ignored.
    for variant_id, expected_text in expected.items():
        path = variants.get(variant_id)
        if path is None:
            raise ValueError(f"locked variant is missing: {variant_id}")
        if path.read_text(encoding="utf-8") != expected_text:
            raise ValueError(f"{variant_id} differs from its single authorized block")
