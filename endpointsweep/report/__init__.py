"""Report renderers: Markdown (primary), SARIF (tooling), HTML (shareable)."""

from __future__ import annotations

from .html import fleet_report_html
from .markdown import fleet_report_markdown, host_report_markdown
from .sarif import dumps as sarif_dumps
from .sarif import fleet_sarif, host_sarif

__all__ = [
    "fleet_report_html",
    "fleet_report_markdown",
    "fleet_sarif",
    "host_report_markdown",
    "host_sarif",
    "sarif_dumps",
]
