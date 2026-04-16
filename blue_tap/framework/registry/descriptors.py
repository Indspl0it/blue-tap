"""Module metadata descriptors."""

from __future__ import annotations

import re
from dataclasses import dataclass

from blue_tap.framework.registry.families import ModuleFamily


@dataclass(frozen=True)
class ModuleDescriptor:
    module_id: str
    family: ModuleFamily
    name: str
    description: str
    protocols: tuple[str, ...]
    requires: tuple[str, ...]
    destructive: bool
    requires_pairing: bool
    schema_prefix: str
    has_report_adapter: bool
    entry_point: str
    internal: bool = False
    report_adapter_path: str | None = None
    """Dotted import path to the ReportAdapter class for this module.

    Format: ``'package.module:ClassName'``. Used by
    :func:`~blue_tap.framework.reporting.adapters.get_report_adapters` to
    dynamically load third-party adapters registered via the plugin system.
    Built-in adapters leave this ``None`` and are listed in the static
    ``REPORT_ADAPTERS`` tuple instead.

    Example (for a third-party plugin)::

        report_adapter_path="my_plugin.adapters:MyModuleAdapter"
    """

    category: str | None = None
    """Sub-category within a family (e.g., 'pairing', 'l2cap', 'ble' for DoS)."""

    references: tuple[str, ...] = ()
    """External references (CVEs, RFCs, specifications) associated with the module."""

    def __post_init__(self) -> None:
        if not re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", self.module_id):
            raise ValueError(
                f"module_id must be '<family>.<name>' in snake_case, got {self.module_id!r}"
            )
        if not isinstance(self.family, ModuleFamily):
            raise ValueError(f"family must be a ModuleFamily enum, got {type(self.family)}")
        if not self.module_id.startswith(self.family.value + "."):
            raise ValueError(
                f"module_id {self.module_id!r} must start with family {self.family.value!r}"
            )
        if not self.name:
            raise ValueError("name must be non-empty")
        if not isinstance(self.protocols, tuple):
            raise ValueError(f"protocols must be a tuple, got {type(self.protocols)}")
        if not isinstance(self.requires, tuple):
            raise ValueError(f"requires must be a tuple, got {type(self.requires)}")
