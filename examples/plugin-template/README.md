# Blue-Tap Plugin Template

Minimal working example of a third-party Blue-Tap plugin. Copy this
directory, rename the package, edit the module body, and you have your own
plugin.

## What it does

Registers one assessment-family module called `assessment.example_no_op`
that always returns `not_applicable`. It touches no hardware. Its only
purpose is to demonstrate the wiring.

## Wiring

```
plugin-template/
├── pyproject.toml                          # entry-point declaration
└── bluetap_example_plugin/
    └── __init__.py                          # Module subclass(es) live here
```

The two pieces that matter:

1. **`pyproject.toml`** declares an entry point under the
   `blue_tap.modules` group:

   ```toml
   [project.entry-points."blue_tap.modules"]
   bluetap_example_plugin = "bluetap_example_plugin"
   ```

   The right-hand string is any importable Python module path. Whatever
   that import does, it must (eventually) define `Module` subclasses.

2. **`bluetap_example_plugin/__init__.py`** subclasses
   `blue_tap.framework.module.Module`. The `__init_subclass__` hook on
   `Module` auto-registers the descriptor with the global registry — no
   explicit `register()` call needed.

## Try it

```bash
# 1. Install your plugin (editable so you can iterate on it).
cd examples/plugin-template
pip install -e .

# 2. Confirm Blue-Tap discovers it.
blue-tap plugins list
# Expected: bluetap_example_plugin appears in the list

# 3. See its metadata.
blue-tap info assessment.example_no_op

# 4. Invoke it.
blue-tap run assessment.example_no_op RHOST=AA:BB:CC:DD:EE:FF
# The run completes, the session log includes a ``not_applicable`` envelope.

# 5. Uninstall when done.
pip uninstall bluetap-example-plugin
```

## Building a real plugin from this template

1. **Rename the package** — change `bluetap_example_plugin` everywhere:
   - the directory name
   - `[project] name` and the entry-point key in `pyproject.toml`
   - the `module_id` of every module you define (must start with a real
     family value: `assessment.`, `exploitation.`, `reconnaissance.`,
     `post_exploitation.`, `fuzzing.`, `discovery.`)

2. **Replace the no-op `run()`** with your real logic. Return a
   `RunEnvelope` (use the `build_run_envelope` / `make_execution` helpers
   from `blue_tap.framework.contracts.result_schema`). Set
   `module_outcome` to a value valid for your family — see
   `blue_tap.framework.registry.families.FAMILY_OUTCOMES`.

3. **Declare options** that the operator passes via `KEY=VALUE`. Use the
   helpers in `blue_tap.framework.module.options`:
   `OptString`, `OptInt`, `OptBool`, `OptAddress`, `OptChoice`.

4. **(Optional) Add a report adapter** if your module emits findings that
   should appear in `blue-tap report`. Set
   `has_report_adapter = True` and `report_adapter_path =
   "your_pkg.adapters:YourAdapter"`. The adapter class must extend
   `blue_tap.framework.contracts.report_contract.ReportAdapter`.

## Reading material

* `blue_tap/framework/module/base.py` — the `Module` ABC, all class-level
  metadata fields, and the `__init_subclass__` registration hook.
* `blue_tap/framework/contracts/result_schema.py` — `RunEnvelope`,
  `ExecutionRecord`, `Evidence`, helper builders.
* `blue_tap/framework/registry/families.py` — the `ModuleFamily` enum and
  the `FAMILY_OUTCOMES` map (which `module_outcome` strings each family
  accepts).
* `blue_tap/modules/discovery/scanner.py` — a small real module worth
  reading for shape.
