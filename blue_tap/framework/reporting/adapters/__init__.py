"""Registry of report adapters for standardized module envelopes."""

from blue_tap.framework.reporting.adapters.attack import AttackReportAdapter
from blue_tap.framework.reporting.adapters.audio import AudioReportAdapter
from blue_tap.framework.reporting.adapters.auto import AutoReportAdapter
from blue_tap.framework.reporting.adapters.data import DataReportAdapter
from blue_tap.framework.reporting.adapters.discovery import DiscoveryReportAdapter
from blue_tap.framework.reporting.adapters.dos import DosReportAdapter
from blue_tap.framework.reporting.adapters.firmware import FirmwareReportAdapter
from blue_tap.framework.reporting.adapters.fuzz import FuzzReportAdapter
from blue_tap.framework.reporting.adapters.lmp_capture import LmpCaptureReportAdapter
from blue_tap.framework.reporting.adapters.recon import ReconReportAdapter
from blue_tap.framework.reporting.adapters.spoof import SpoofReportAdapter
from blue_tap.framework.reporting.adapters.vulnscan import VulnscanReportAdapter


import importlib
import logging

_logger = logging.getLogger(__name__)

REPORT_ADAPTERS = (
    DiscoveryReportAdapter(),
    VulnscanReportAdapter(),
    AttackReportAdapter(),
    AutoReportAdapter(),
    DataReportAdapter(),
    AudioReportAdapter(),
    DosReportAdapter(),
    FirmwareReportAdapter(),
    FuzzReportAdapter(),
    LmpCaptureReportAdapter(),
    ReconReportAdapter(),
    SpoofReportAdapter(),
)

# Set of module names already covered by the static tuple — used to avoid duplicates
_BUILTIN_MODULES: frozenset[str] = frozenset(a.module for a in REPORT_ADAPTERS)


def get_report_adapters() -> tuple:
    """Return all active report adapters: built-in static ones plus any registered
    via the framework registry through ``report_adapter_path``.

    Third-party plugins advertise their adapter by setting ``report_adapter_path``
    on their :class:`~blue_tap.framework.registry.ModuleDescriptor`.  This function
    imports those classes at call time (lazy) and appends them to the static tuple.

    Returns:
        Tuple of :class:`~blue_tap.framework.contracts.report_contract.ReportAdapter`
        instances.  Safe to call multiple times (re-imports on each call; callers
        should cache the result if performance matters).
    """
    from blue_tap.framework.registry import get_registry

    extra: list = []
    try:
        registry = get_registry()
        for desc in registry.list_all():
            if not desc.report_adapter_path:
                continue
            if desc.module_id.split(".", 1)[1] in _BUILTIN_MODULES:
                # Built-in module — already covered by the static tuple
                continue
            try:
                module_path, class_name = desc.report_adapter_path.rsplit(":", 1)
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                extra.append(cls())
                _logger.debug(
                    "Loaded plugin report adapter %s for module %s",
                    desc.report_adapter_path,
                    desc.module_id,
                )
            except Exception as exc:
                _logger.warning(
                    "Failed to load report adapter %r for module %s: %s",
                    desc.report_adapter_path,
                    desc.module_id,
                    exc,
                )
    except Exception as exc:
        _logger.warning("Registry unavailable when loading report adapters: %s", exc)

    if extra:
        return REPORT_ADAPTERS + tuple(extra)
    return REPORT_ADAPTERS


def get_adapters_for_report(schema: str) -> list:
    """Return report adapters that can handle the given schema string.

    Includes both built-in and plugin adapters (via :func:`get_report_adapters`).
    """
    probe = {"schema": schema}
    return [a for a in get_report_adapters() if a.accepts(probe)]


__all__ = [
    "AttackReportAdapter",
    "AudioReportAdapter",
    "AutoReportAdapter",
    "DataReportAdapter",
    "DiscoveryReportAdapter",
    "DosReportAdapter",
    "FirmwareReportAdapter",
    "FuzzReportAdapter",
    "LmpCaptureReportAdapter",
    "ReconReportAdapter",
    "REPORT_ADAPTERS",
    "SpoofReportAdapter",
    "VulnscanReportAdapter",
    "get_adapters_for_report",
    "get_report_adapters",
]
