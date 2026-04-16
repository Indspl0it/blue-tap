"""Module ABC and related base classes for Blue-Tap modules.

Every module (CVE check, exploit, DoS probe, etc.) inherits from Module
or is wrapped with the function_module decorator.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from blue_tap.framework.module.context import RunContext
    from blue_tap.framework.module.options import Opt

from blue_tap.framework.registry import ModuleDescriptor, ModuleFamily, get_registry

logger = logging.getLogger(__name__)


class Module(ABC):
    """Abstract base class for all Blue-Tap modules.

    Subclasses define class attributes for metadata and options, then implement
    run() to return a RunEnvelope. The __init_subclass__ hook automatically
    registers the module with the global registry.

    Example:
        class MyExploit(Module):
            module_id = "exploitation.my_exploit"
            family = ModuleFamily.EXPLOITATION
            name = "My Exploit"
            description = "Does something exploitative."
            protocols = ("Classic", "L2CAP")
            destructive = True
            options = (
                OptAddress("RHOST", required=True),
                OptInt("COUNT", default=10, min=1),
            )

            def run(self, ctx: RunContext) -> dict:
                return build_attack_result(...)
    """

    # Class-level metadata
    module_id: str = ""
    family: ModuleFamily = ModuleFamily.DISCOVERY
    name: str = ""
    description: str = ""
    protocols: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    destructive: bool = False
    requires_pairing: bool = False
    references: tuple[str, ...] = ()  # CVEs, papers, URLs
    options: tuple[Opt, ...] = ()
    schema_prefix: str = ""
    has_report_adapter: bool = False
    internal: bool = False
    category: str | None = None  # Sub-category within family
    report_adapter_path: str | None = None  # Custom adapter class path

    # Mark abstract base classes with _abstract = True to skip registration
    _abstract: bool = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register the module descriptor on class definition."""
        super().__init_subclass__(**kwargs)

        # Skip abstract classes (check cls.__dict__ to avoid inheriting from parent)
        if cls.__dict__.get("_abstract", False):
            return

        # Skip if no module_id (incomplete subclass)
        if not cls.module_id:
            logger.debug("Skipping registration for %s: no module_id", cls.__name__)
            return

        desc = ModuleDescriptor(
            module_id=cls.module_id,
            family=cls.family,
            name=cls.name,
            description=cls.description,
            protocols=cls.protocols,
            requires=cls.requires,
            destructive=cls.destructive,
            requires_pairing=cls.requires_pairing,
            schema_prefix=cls.schema_prefix,
            has_report_adapter=cls.has_report_adapter,
            entry_point=f"{cls.__module__}:{cls.__name__}",
            internal=cls.internal,
            report_adapter_path=cls.report_adapter_path,
            category=cls.category,
            references=cls.references,
        )

        try:
            get_registry().register(desc)
            logger.debug("Registered module: %s", desc.module_id)
        except ValueError:
            # Already registered (re-import during tests)
            logger.debug("Module already registered: %s", desc.module_id)

    @abstractmethod
    def run(self, ctx: RunContext) -> dict:
        """Execute the module and return a RunEnvelope dict.

        The envelope must follow the schema in framework/contracts/result_schema.py.
        """
        raise NotImplementedError

    def cleanup(self, ctx: RunContext) -> None:
        """Optional teardown after run/check.

        Called even if run() raises. Override to release resources.
        """
        pass


def function_module(
    *,
    module_id: str,
    family: ModuleFamily,
    name: str,
    description: str,
    protocols: tuple[str, ...] = (),
    requires: tuple[str, ...] = (),
    destructive: bool = False,
    requires_pairing: bool = False,
    references: tuple[str, ...] = (),
    options: tuple = (),
    schema_prefix: str = "",
    has_report_adapter: bool = False,
    internal: bool = False,
    category: str | None = None,
    report_adapter_path: str | None = None,
) -> Callable[[Callable], type[Module]]:
    """Decorator to wrap a function as a Module subclass.

    Enables mechanical migration of existing check functions without
    rewriting them as full classes.

    Example:
        @function_module(
            module_id="assessment.cve_2017_0785",
            family=ModuleFamily.ASSESSMENT,
            name="SDP Continuation Info Leak",
            description="CVE-2017-0785 check",
            options=(OptAddress("RHOST", required=True),),
            references=("CVE-2017-0785",),
        )
        def cve_2017_0785(RHOST: str) -> dict:
            return _check_sdp_continuation(RHOST)
    """

    def decorator(fn: Callable) -> type[Module]:
        # Create a new Module subclass dynamically
        class _FunctionModule(Module):
            pass

        # Set class attributes
        _FunctionModule.module_id = module_id
        _FunctionModule.family = family
        _FunctionModule.name = name
        _FunctionModule.description = description
        _FunctionModule.protocols = protocols
        _FunctionModule.requires = requires
        _FunctionModule.destructive = destructive
        _FunctionModule.requires_pairing = requires_pairing
        _FunctionModule.references = references
        _FunctionModule.options = options
        _FunctionModule.schema_prefix = schema_prefix
        _FunctionModule.has_report_adapter = has_report_adapter
        _FunctionModule.internal = internal
        _FunctionModule.category = category
        _FunctionModule.report_adapter_path = report_adapter_path

        import inspect
        _fn_sig = inspect.signature(fn)
        _fn_accepts_kwargs = any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in _fn_sig.parameters.values()
        )
        _fn_param_names = {p.name for p in _fn_sig.parameters.values()}

        def run(self: Module, ctx: RunContext) -> dict:
            """Call the wrapped function with options as kwargs."""
            all_options = ctx.options.as_dict()
            if _fn_accepts_kwargs:
                call_kwargs = all_options
            else:
                call_kwargs = {
                    k: v for k, v in all_options.items()
                    if k in _fn_param_names or k.lower() in _fn_param_names
                }
            try:
                return fn(**call_kwargs)
            except TypeError as e:
                logger.error(
                    "Function %s signature mismatch. Provided kwargs: %s. Error: %s",
                    fn.__name__,
                    list(call_kwargs.keys()),
                    e,
                )
                raise

        _FunctionModule.run = run  # type: ignore[method-assign]
        _FunctionModule.__abstractmethods__ = frozenset()
        _FunctionModule.__name__ = fn.__name__
        _FunctionModule.__qualname__ = fn.__qualname__
        _FunctionModule.__doc__ = fn.__doc__

        # Trigger registration by setting module_id after class creation
        # (The class was created with module_id="" so __init_subclass__ skipped it)
        # We need to manually register now
        desc = ModuleDescriptor(
            module_id=module_id,
            family=family,
            name=name,
            description=description,
            protocols=protocols,
            requires=requires,
            destructive=destructive,
            requires_pairing=requires_pairing,
            schema_prefix=schema_prefix,
            has_report_adapter=has_report_adapter,
            entry_point=f"{_FunctionModule.__module__}:{_FunctionModule.__name__}",
            internal=internal,
            report_adapter_path=report_adapter_path,
            category=category,
            references=references,
        )
        try:
            get_registry().register(desc)
        except ValueError:
            pass  # Already registered

        return _FunctionModule

    return decorator
