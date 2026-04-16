"""Target discovery and inventory collection.

The native ``ScannerModule`` lives in ``scanner.py`` next to its hardware
call path. Importing it here triggers Module auto-registration. There is
no separate ``discovery/modules/`` wrapper package — that layer was
collapsed on 2026-04-12.
"""

from blue_tap.modules.discovery import scanner  # noqa: F401
