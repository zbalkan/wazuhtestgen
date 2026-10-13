"""Explicit, reviewed ATT&CK ID compatibility exceptions for Wazuh v4.14.x.

Key: Sigma / modern Enterprise ATT&CK technique ID.
Value: expected technique ID in the target Wazuh ATT&CK taxonomy.

Keep this table intentionally small. Add pairs only after validating the
historical technique relationship; do not derive mappings from names or
implicitly truncate subtechniques. Every other ID passes through unchanged.
"""
from __future__ import annotations

# No verified exceptions registered yet.
ATTACK_ID_OVERRIDES: dict[str, str] = {}


def map_attack_id(technique_id: str) -> str:
    """Map a normalized Txxxx[.xxx] ID; identity unless explicitly overridden."""
    normalized = technique_id.upper()
    return ATTACK_ID_OVERRIDES.get(normalized, normalized)
