"""Report adapter contracts, module-specific adapters, and HTML/JSON renderers."""

from blue_tap.framework.reporting.adapters import REPORT_ADAPTERS, get_adapters_for_report, get_report_adapters
from blue_tap.framework.reporting.renderers import render_sections

__all__ = [
    "REPORT_ADAPTERS",
    "get_adapters_for_report",
    "get_report_adapters",
    "render_sections",
]
