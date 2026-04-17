"""Option type definitions for Blue-Tap modules.

Typed option declarations similar to Metasploit's Opt* types.
Each Opt subclass validates and coerces values from raw input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class OptionError(Exception):
    """Raised when option validation fails."""

    def __init__(self, option_name: str, message: str) -> None:
        self.option_name = option_name
        self.message = message
        super().__init__(f"{option_name}: {message}")


# Bluetooth MAC address pattern: AA:BB:CC:DD:EE:FF
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


@dataclass(frozen=True, slots=True)
class Opt:
    """Base option class.

    All option types inherit from this and implement validate().
    """

    name: str
    required: bool = False
    default: Any = None
    description: str = ""

    def validate(self, value: Any) -> Any:
        """Validate and coerce value. Raises OptionError on failure."""
        raise NotImplementedError(f"{self.__class__.__name__}.validate")


@dataclass(frozen=True, slots=True)
class OptString(Opt):
    """String option with optional regex pattern validation."""

    pattern: str | None = None
    min_length: int = 0
    max_length: int = 0  # 0 = no limit

    def validate(self, value: Any) -> str:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            return self.default or ""

        s = str(value).strip()

        if self.min_length and len(s) < self.min_length:
            raise OptionError(self.name, f"must be at least {self.min_length} characters")

        if self.max_length and len(s) > self.max_length:
            raise OptionError(self.name, f"must be at most {self.max_length} characters")

        if self.pattern and not re.match(self.pattern, s):
            raise OptionError(self.name, f"must match pattern: {self.pattern}")

        return s


@dataclass(frozen=True, slots=True)
class OptInt(Opt):
    """Integer option with optional bounds."""

    min: int | None = None
    max: int | None = None

    def validate(self, value: Any) -> int | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default is not None:
                return int(self.default)
            return None

        try:
            n = int(value)
        except (TypeError, ValueError):
            raise OptionError(self.name, f"must be an integer, got {value!r}") from None

        if self.min is not None and n < self.min:
            raise OptionError(self.name, f"must be >= {self.min}, got {n}")

        if self.max is not None and n > self.max:
            raise OptionError(self.name, f"must be <= {self.max}, got {n}")

        return n


@dataclass(frozen=True, slots=True)
class OptFloat(Opt):
    """Float option with optional bounds."""

    min: float | None = None
    max: float | None = None

    def validate(self, value: Any) -> float | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default is not None:
                return float(self.default)
            return None

        try:
            n = float(value)
        except (TypeError, ValueError):
            raise OptionError(self.name, f"must be a number, got {value!r}") from None

        if self.min is not None and n < self.min:
            raise OptionError(self.name, f"must be >= {self.min}, got {n}")

        if self.max is not None and n > self.max:
            raise OptionError(self.name, f"must be <= {self.max}, got {n}")

        return n


@dataclass(frozen=True, slots=True)
class OptBool(Opt):
    """Boolean option. Accepts: true/false, yes/no, 1/0, on/off."""

    def validate(self, value: Any) -> bool:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            return bool(self.default)

        if isinstance(value, bool):
            return value

        if isinstance(value, int):
            return bool(value)

        if isinstance(value, str):
            lower = value.lower().strip()
            if lower in ("true", "yes", "1", "on"):
                return True
            if lower in ("false", "no", "0", "off"):
                return False

        raise OptionError(
            self.name,
            f"must be boolean (true/false, yes/no, 1/0), got {value!r}",
        )


@dataclass(frozen=True, slots=True)
class OptAddress(Opt):
    """Bluetooth MAC address option. Format: AA:BB:CC:DD:EE:FF."""

    def validate(self, value: Any) -> str | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default:
                return str(self.default).upper()
            return None

        addr = str(value).strip()
        if not _MAC_RE.match(addr):
            raise OptionError(
                self.name,
                f"must be MAC address (AA:BB:CC:DD:EE:FF), got {addr!r}",
            )
        return addr.upper()


@dataclass(frozen=True, slots=True)
class OptPort(Opt):
    """Port number option. Default range: 1-65535."""

    min: int = 1
    max: int = 65535

    def validate(self, value: Any) -> int | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default is not None:
                return int(self.default)
            return None

        try:
            n = int(value)
        except (TypeError, ValueError):
            raise OptionError(self.name, f"must be a port number, got {value!r}") from None

        if n < self.min or n > self.max:
            raise OptionError(self.name, f"must be between {self.min}-{self.max}, got {n}")

        return n


@dataclass(frozen=True, slots=True)
class OptEnum(Opt):
    """Enum option: value must be one of a fixed set of choices."""

    choices: tuple[str, ...] = ()
    case_sensitive: bool = True

    def validate(self, value: Any) -> str | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default:
                return str(self.default)
            return None

        s = str(value).strip()

        if self.case_sensitive:
            if s in self.choices:
                return s
        else:
            # Case-insensitive: return the canonical choice
            lower = s.lower()
            for choice in self.choices:
                if choice.lower() == lower:
                    return choice

        raise OptionError(
            self.name,
            f"must be one of [{', '.join(self.choices)}], got {s!r}",
        )


# Alias for clarity in CVE checks
OptChoice = OptEnum


@dataclass(frozen=True, slots=True)
class OptPath(Opt):
    """Filesystem path option with optional existence checks."""

    must_exist: bool = False
    must_be_file: bool = False
    must_be_dir: bool = False

    def validate(self, value: Any) -> str | None:
        if value is None:
            if self.required:
                raise OptionError(self.name, "is required")
            if self.default:
                return str(self.default)
            return None

        path_str = str(value).strip()

        if not self.must_exist:
            return path_str

        path = Path(path_str)
        if not path.exists():
            raise OptionError(self.name, f"path does not exist: {path_str}")

        if self.must_be_file and not path.is_file():
            raise OptionError(self.name, f"must be a file: {path_str}")

        if self.must_be_dir and not path.is_dir():
            raise OptionError(self.name, f"must be a directory: {path_str}")

        return path_str
