# bt-example-plugin

Minimal Blue-Tap plugin demonstrating the module extension mechanism.

## How it works

1. The plugin advertises a `ModuleDescriptor` via the `blue_tap.modules` entry-point group in `pyproject.toml`.
2. When `blue_tap.framework.registry.load_plugins()` is called (or `blue-tap list-modules` runs), Blue-Tap imports the descriptor and registers the module.
3. The module then appears in `blue-tap list-modules` and can be invoked via the registry.

## Installing locally (for testing)

```bash
pip install -e tests/fixtures/example_plugin/
python -c "from blue_tap.framework.registry import load_plugins; print(load_plugins())"
# Should print: ['exploitation.example_ping']
```

## Plugin structure

```
bt_example_plugin/
  __init__.py      # exports DESCRIPTOR (the ModuleDescriptor entry-point value)
  module.py        # ExamplePingAttack implementation
pyproject.toml     # declares blue_tap.modules entry point
```

## Adding a report adapter

Set `has_report_adapter=True` and `report_adapter_path="bt_example_plugin.adapter:ExampleAdapter"` on the descriptor, then implement the `ReportAdapter` ABC:

```python
# bt_example_plugin/adapter.py
from blue_tap.framework.contracts.report_contract import ReportAdapter, SectionModel

class ExampleAdapter(ReportAdapter):
    module = "example_ping"

    def accepts(self, envelope: dict) -> bool:
        return envelope.get("schema", "").startswith("blue_tap.attack.")

    def ingest(self, envelope: dict, state: dict) -> None:
        state.setdefault("runs", []).append(envelope)

    def render(self, state: dict) -> list[SectionModel]:
        return []
```
