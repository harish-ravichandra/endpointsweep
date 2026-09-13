"""Check catalog. Importing this package populates the registry.

Families: ``caps`` (ES-1xx), ``injection`` (ES-2xx), ``supplychain`` (ES-3xx),
``hygiene`` (ES-4xx), ``fleet`` (ES-9xx).
"""

from __future__ import annotations

from . import caps, fleet, hygiene, injection, supplychain  # noqa: F401  (registration side effect)
from .registry import (
    REGISTRY,
    Check,
    CheckContext,
    CheckMeta,
    all_checks,
    run_fleet_checks,
    run_host_checks,
)

__all__ = [
    "REGISTRY",
    "Check",
    "CheckContext",
    "CheckMeta",
    "all_checks",
    "run_fleet_checks",
    "run_host_checks",
]
