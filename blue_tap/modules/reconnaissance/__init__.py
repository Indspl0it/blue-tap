"""Deep per-target enumeration, fingerprinting, service mapping, and protocol surface analysis.

All reconnaissance Module subclasses live next to their helper code in the
individual family files (``sdp.py``, ``gatt.py``, ``l2cap_scan.py``, ...).
Importing those files here triggers ``Module.__init_subclass__`` which
auto-registers each Module with ``framework.registry``. There is no
separate ``reconnaissance/modules/`` wrapper package — that layer was
collapsed on 2026-04-12.
"""

# Import each legacy-helper file. Each import triggers the side-effect of
# registering its Module subclass (via __init_subclass__). Some imports are
# chained (e.g. capture_analysis imports correlation internally) so order
# matters: base modules first, then the ones that depend on them.

from blue_tap.modules.reconnaissance import sdp  # noqa: F401
from blue_tap.modules.reconnaissance import gatt  # noqa: F401
from blue_tap.modules.reconnaissance import l2cap_scan  # noqa: F401
from blue_tap.modules.reconnaissance import rfcomm_scan  # noqa: F401
from blue_tap.modules.reconnaissance import hci_capture  # noqa: F401
from blue_tap.modules.reconnaissance import sniffer  # noqa: F401
from blue_tap.modules.reconnaissance import fingerprint  # noqa: F401
from blue_tap.modules.reconnaissance import capability_detector  # noqa: F401
from blue_tap.modules.reconnaissance import correlation  # noqa: F401
from blue_tap.modules.reconnaissance import capture_analysis  # noqa: F401
from blue_tap.modules.reconnaissance import prerequisites  # noqa: F401
from blue_tap.modules.reconnaissance import spec_interpretation  # noqa: F401
from blue_tap.modules.reconnaissance import campaign  # noqa: F401
