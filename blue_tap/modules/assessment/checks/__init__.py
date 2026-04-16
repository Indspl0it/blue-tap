"""CVE and non-CVE check implementations.

This package contains the underlying check functions AND the native Module
subclasses that wrap them. Module subclasses are defined at the bottom of
each check file and auto-register via __init_subclass__ at import time.
"""

from blue_tap.modules.assessment.checks import (  # noqa: F401
    cve_sdp,
    cve_l2cap,
    cve_bnep,
    cve_avrcp,
    cve_gatt,
    cve_airoha,
    cve_ble_smp,
    cve_pairing,
    cve_hid,
    cve_raw_acl,
    non_cve_ble,
    non_cve_rfcomm,
    non_cve_posture,
)
