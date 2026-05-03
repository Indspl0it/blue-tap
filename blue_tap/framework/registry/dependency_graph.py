"""Best-effort static dependency graph between registered modules.

Resolves *which other modules each registered module imports*, by parsing the
source file referenced by the descriptor's ``entry_point`` (and the source of
every Python file in the same package, since most call sites are nested deep
in handler classes that span multiple files).

Built lazily: nothing computes until :func:`get_dependencies` is called for
the first time, then the full graph is cached as a module-level singleton.
``info_cmd`` is the only consumer today.

Detection limits — surface honestly rather than overclaim:

* Only ``from blue_tap.modules.<family>.<name>[.subpath]`` imports count. Any
  module that's referenced by string (``importlib.import_module``,
  ``entry_points``, ``getattr``) is invisible.
* Imports inside conditional branches (``try/except ImportError``, ``if
  TYPE_CHECKING``) still count — they're sources of *potential* runtime
  dependency.
* Self-imports inside the same module package are excluded (a module
  trivially depends on itself).
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DependencyEdges:
    """Per-module dependency view."""

    depends_on: tuple[str, ...] = ()
    """Module IDs this module imports from."""

    used_by: tuple[str, ...] = ()
    """Module IDs that import from this one."""


@dataclass
class _GraphCache:
    """Internal cache populated on first call to :func:`get_dependencies`."""

    by_module: dict[str, DependencyEdges] = field(default_factory=dict)
    built: bool = False


_cache = _GraphCache()


# ── Public API ───────────────────────────────────────────────────────────


def get_dependencies(module_id: str) -> DependencyEdges:
    """Return the dependency edges for ``module_id``.

    Missing modules return an empty :class:`DependencyEdges` rather than
    raising — the dependency view is informational and a missing entry is
    not an error.
    """
    if not _cache.built:
        _build_graph()
    return _cache.by_module.get(module_id, DependencyEdges())


def reset_cache() -> None:
    """Forget the cached graph; the next ``get_dependencies`` call rebuilds it.

    Called by :class:`ModuleRegistry.register` / ``unregister`` so plugins
    registered after the first graph build are not silently absent from the
    dependency view. Also used directly by tests that mutate the registry.
    """
    _cache.by_module.clear()
    _cache.built = False


# ── Internal builders ────────────────────────────────────────────────────


def _build_graph() -> None:
    """Walk the registry, parse every module's package source, build the cache."""
    from blue_tap.framework.registry.registry import get_registry

    registry = get_registry()
    descriptors = list(registry.list_all())

    # Forward edges: module_id -> set of module_ids it imports from
    forward: dict[str, set[str]] = {d.module_id: set() for d in descriptors}

    # Pre-compute the package directories owned by each registered module.
    # ``entry_point`` is ``dotted.module.path:ClassName``. The owning package
    # is everything up to and including the leaf (e.g. for
    # ``blue_tap.modules.exploitation.dos.runner`` the package dir is
    # ``blue_tap/modules/exploitation/dos`` — its full subtree).
    pkg_dir_for: dict[str, Path] = {}
    for descriptor in descriptors:
        module_path = descriptor.entry_point.split(":", 1)[0]
        pkg_dir = _resolve_package_dir(module_path)
        if pkg_dir is not None:
            pkg_dir_for[descriptor.module_id] = pkg_dir

    # For each registered module, parse every .py file under its package
    # directory and record imports of the form
    # ``from blue_tap.modules.<family>.<name>[.subpath]``.
    for descriptor in descriptors:
        pkg_dir = pkg_dir_for.get(descriptor.module_id)
        if pkg_dir is None:
            continue
        for py_file in pkg_dir.rglob("*.py"):
            try:
                imported_modules = _imported_module_ids(py_file)
            except OSError:
                continue
            except SyntaxError as exc:
                logger.debug("Skipping unparseable file %s: %s", py_file, exc)
                continue
            for imported in imported_modules:
                if imported == descriptor.module_id:
                    continue  # self-import — don't count
                if imported in forward:
                    forward[descriptor.module_id].add(imported)

    # Build the reverse edges in one pass.
    reverse: dict[str, set[str]] = {mid: set() for mid in forward}
    for src, targets in forward.items():
        for tgt in targets:
            reverse.setdefault(tgt, set()).add(src)

    _cache.by_module = {
        mid: DependencyEdges(
            depends_on=tuple(sorted(forward.get(mid, set()))),
            used_by=tuple(sorted(reverse.get(mid, set()))),
        )
        for mid in {*forward.keys(), *reverse.keys()}
    }
    _cache.built = True


def _resolve_package_dir(dotted_module: str) -> Path | None:
    """Resolve ``blue_tap.modules.foo.bar`` to its on-disk directory.

    Returns the directory of the leaf if it's a package (has ``__init__.py``)
    OR the directory of the parent if the leaf is a single ``.py`` file.
    """
    parts = dotted_module.split(".")
    repo_root = Path(__file__).resolve().parents[3]
    candidate = repo_root.joinpath(*parts)
    if candidate.is_dir() and (candidate / "__init__.py").exists():
        return candidate
    leaf_file = candidate.with_suffix(".py")
    if leaf_file.is_file():
        return leaf_file.parent
    return None


def _imported_module_ids(py_file: Path) -> set[str]:
    """Parse ``py_file`` and return module_ids matching its blue_tap.modules imports.

    Recognises:

    * ``from blue_tap.modules.<family>.<name> import ...`` → ``<family>.<name>``
    * ``from blue_tap.modules.<family>.<name>.<subpath> import ...`` →
      ``<family>.<name>``  (the leaf module under a package counts as a
      dependency on the package's registered module)
    * ``import blue_tap.modules.<family>.<name>`` → ``<family>.<name>``

    Anything not under ``blue_tap.modules.`` is ignored.
    """
    try:
        source = py_file.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return set()
    tree = ast.parse(source, filename=str(py_file))

    found: set[str] = set()
    prefix = "blue_tap.modules."

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith(prefix):
                found.add(_module_id_from_dotted(mod[len(prefix):]))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(prefix):
                    found.add(_module_id_from_dotted(alias.name[len(prefix):]))

    return {m for m in found if m}


def _module_id_from_dotted(remainder: str) -> str:
    """Convert ``family.name[.deeper.path]`` to canonical ``family.name`` module_id.

    Returns empty string if the input doesn't have at least two segments.
    """
    parts = remainder.split(".")
    if len(parts) < 2:
        return ""
    return f"{parts[0]}.{parts[1]}"
