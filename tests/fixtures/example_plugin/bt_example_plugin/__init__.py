"""Example Blue-Tap plugin — demonstrates the module extension API.

This is a minimal third-party plugin that shows how to:
  1. Create a ModuleDescriptor and register via entry points
  2. Optionally ship a ReportAdapter alongside the module

Install this plugin (in a real project) with::

    pip install bt-example-plugin

Then Blue-Tap discovers it automatically via the ``blue_tap.modules`` entry-point
group defined in this package's ``pyproject.toml``.
"""

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily

# The descriptor exported as the entry-point value.
# pyproject.toml points to: bt_example_plugin:DESCRIPTOR
DESCRIPTOR = ModuleDescriptor(
    module_id="exploitation.example_ping",
    family=ModuleFamily.EXPLOITATION,
    name="Example Ping Attack",
    description="Minimal example plugin — sends a crafted L2CAP echo and measures response",
    protocols=("Classic", "L2CAP"),
    requires=("adapter", "classic_target"),
    destructive=False,
    requires_pairing=False,
    schema_prefix="blue_tap.attack.result",
    has_report_adapter=False,
    entry_point="bt_example_plugin.module:ExamplePingAttack",
    internal=False,
)
