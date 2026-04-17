"""Registry of report adapters for standardized module envelopes."""

from blue_tap.framework.reporting.adapters.attack import AttackReportAdapter
from blue_tap.framework.reporting.adapters.audio import AudioReportAdapter
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
    DataReportAdapter(),
    AudioReportAdapter(),
    DosReportAdapter(),
    FirmwareReportAdapter(),
    FuzzReportAdapter(),
    LmpCaptureReportAdapter(),
    ReconReportAdapter(),
    SpoofReportAdapter(),
)

# Set of adapter class identities already covered by the static tuple
_BUILTIN_ADAPTER_CLASSES: frozenset[type] = frozenset(type(a) for a in REPORT_ADAPTERS)


def get_report_adapters() -> tuple:
    """Return all active report adapters, ordered by ``priority`` (ascending)."""
    from blue_tap.framework.registry import get_registry

    all_adapters: list = list(REPORT_ADAPTERS)
    seen_classes: set[type] = set(_BUILTIN_ADAPTER_CLASSES)
    try:
        registry = get_registry()
        for desc in registry.list_all():
            if not desc.report_adapter_path:
                continue
            try:
                module_path, class_name = desc.report_adapter_path.rsplit(":", 1)
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                if cls in seen_classes:
                    continue
                instance = cls()
                if "priority" not in cls.__dict__ and instance.priority == 100:
                    instance.priority = 50
                all_adapters.append(instance)
                seen_classes.add(cls)
                _logger.debug(
                    "Loaded plugin report adapter %s for module %s (priority=%d)",
                    desc.report_adapter_path,
                    desc.module_id,
                    instance.priority,
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

    all_adapters.sort(key=lambda a: getattr(a, "priority", 100))
    return tuple(all_adapters)


def get_adapters_for_report(schema: str) -> list:
    """Return report adapters that can handle the given schema string.

    Includes both built-in and plugin adapters (via :func:`get_report_adapters`).
    """
    probe = {"schema": schema}
    return [a for a in get_report_adapters() if a.accepts(probe)]


__all__ = [
    "AttackReportAdapter",
    "AudioReportAdapter",
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
