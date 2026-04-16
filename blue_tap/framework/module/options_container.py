"""Options container for module option validation and access."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

    from blue_tap.framework.module.options import Opt


@dataclass(slots=True)
class OptionsContainer:
    """Container for validated module options.

    Validates option values against a schema and provides dict-like access.

    Usage:
        container = OptionsContainer.from_schema(module.options)
        container.populate({"RHOST": "AA:BB:CC:DD:EE:FF", "COUNT": "10"})
        target = container["RHOST"]
    """

    _schema: dict[str, Opt] = field(default_factory=dict)
    _values: dict[str, Any] = field(default_factory=dict)
    _populated: bool = False

    @classmethod
    def from_schema(cls, schema: tuple[Opt, ...] | None = None) -> OptionsContainer:
        """Create container with the given option schema."""
        container = cls()
        if schema:
            container._schema = {opt.name: opt for opt in schema}
        return container

    def populate(self, raw: Mapping[str, Any] | None = None) -> OptionsContainer:
        """Validate and populate values from raw input.

        Args:
            raw: Dict of option values (typically strings from CLI).

        Returns:
            Self for method chaining.

        Raises:
            OptionError: If validation fails for any option.
        """
        if self._populated:
            return self

        raw = raw or {}

        # Validate each schema option
        for name, opt in self._schema.items():
            raw_value = raw.get(name)
            validated = opt.validate(raw_value)
            self._values[name] = validated

        # Pass through extra options not in schema (forward compatibility)
        for key, value in raw.items():
            if key not in self._schema and value is not None:
                self._values[key] = value

        self._populated = True
        return self

    def get(self, key: str, default: Any = None) -> Any:
        """Get option value with default fallback."""
        return self._values.get(key, default)

    def __getitem__(self, key: str) -> Any:
        """Get option value. Raises KeyError if not set."""
        if key not in self._values:
            raise KeyError(f"Option not set: {key}")
        return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Set option value directly (bypasses validation)."""
        self._values[key] = value

    def __contains__(self, key: str) -> bool:
        """Check if option is set."""
        return key in self._values

    def as_dict(self) -> dict[str, Any]:
        """Return all values as a dict."""
        return self._values.copy()

    def keys(self) -> list[str]:
        """Return list of option names."""
        return list(self._values.keys())

    @property
    def schema(self) -> dict[str, Opt]:
        """Access the option schema."""
        return self._schema
