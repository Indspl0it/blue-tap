"""Blue-Tap Module System.

Provides the Module ABC, Option types, RunContext, and related primitives
for building modular, Metasploit-style modules.
"""

# Base classes
from blue_tap.framework.module.base import Module, function_module

# Option types
from blue_tap.framework.module.options import (
    Opt,
    OptAddress,
    OptBool,
    OptChoice,
    OptEnum,
    OptFloat,
    OptInt,
    OptPath,
    OptPort,
    OptString,
    OptionError,
)

# Container and context
from blue_tap.framework.module.context import RunContext
from blue_tap.framework.module.options_container import OptionsContainer

# Invoker and autoloader
from blue_tap.framework.module.autoload import autoload_builtin_modules
from blue_tap.framework.module.loader import (
    discover_plugins,
    get_plugin_for_module,
    get_plugin_registry,
    load_plugins,
)
from blue_tap.framework.module.invoker import (
    DestructiveConfirmationRequired,
    EntryPointResolutionError,
    Invoker,
    ModuleNotFound,
    NotAModule,
)

__all__ = [
    # Base
    "Module",
    "function_module",
    # Options
    "Opt",
    "OptString",
    "OptInt",
    "OptFloat",
    "OptBool",
    "OptAddress",
    "OptPort",
    "OptEnum",
    "OptChoice",
    "OptPath",
    "OptionError",
    # Container
    "OptionsContainer",
    # Context
    "RunContext",
    # Invoker
    "Invoker",
    "ModuleNotFound",
    "EntryPointResolutionError",
    "NotAModule",
    "DestructiveConfirmationRequired",
    # Autoloader and plugins
    "autoload_builtin_modules",
    "load_plugins",
    "discover_plugins",
    "get_plugin_registry",
    "get_plugin_for_module",
]
