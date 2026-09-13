"""EndpointSweep — fleet-scale MCP and agentic-AI discovery and audit.

Collectors (POSIX sh / bash / PowerShell) inventory endpoints under real
EDR/MDM constraints; this Python package parses, audits and aggregates their
output centrally.
"""

__version__ = "0.1.0"

# Bumped when the on-wire collector JSON contract changes incompatibly.
COLLECTOR_SCHEMA_VERSION = "1"

__all__ = ["__version__", "COLLECTOR_SCHEMA_VERSION"]
