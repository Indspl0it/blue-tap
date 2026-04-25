"""ExamplePingAttack — minimal module implementation for the example plugin."""

from __future__ import annotations


class ExamplePingAttack:
    """Sends a crafted L2CAP echo to the target and reports round-trip latency.

    This is a stub implementation for demonstration purposes.
    A real module would import BluetoothTransport and produce a RunEnvelope.
    """

    def __init__(self, target: str, hci: str = "hci0") -> None:
        self.target = target
        self.hci = hci

    def run(self) -> dict:
        """Execute the attack and return a RunEnvelope dict."""
        from blue_tap.framework.envelopes.attack import build_attack_result

        return build_attack_result(
            module_id="exploitation.attack",
            module="example_ping",
            target=self.target,
            adapter=self.hci,
            executions=[],
            summary={"status": "not_implemented", "note": "example plugin stub"},
            module_data={"plugin": "bt_example_plugin"},
        )
