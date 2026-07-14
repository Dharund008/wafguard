"""Adapter registry with auto-registration.

Importing this package discovers every concrete ``BaseTestAdapter`` subclass
defined in the sibling modules and registers it in ``REGISTRY`` keyed by the
adapter's class name (e.g. "RateLimitAdapter"). The classifier binds each rule
to an adapter by class name, and the engine resolves it here. Adding a new
adapter module requires no edits to this file.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import (
    BaseTestAdapter,
    RequestOutcome,
    TestPayload,
    TestResult,
    Verdict,
)

REGISTRY: dict[str, BaseTestAdapter] = {}


def _discover() -> None:
    package = __name__
    for mod_info in pkgutil.iter_modules(__path__):
        if mod_info.name in {"base"}:
            continue
        module = importlib.import_module(f"{package}.{mod_info.name}")
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseTestAdapter)
                and obj is not BaseTestAdapter
                and obj.__module__ == module.__name__
            ):
                REGISTRY[obj.__name__] = obj()


_discover()


def get_adapter(class_name: str) -> BaseTestAdapter | None:
    """Return the singleton adapter instance for a class name, or None."""
    return REGISTRY.get(class_name)


def all_adapters() -> dict[str, BaseTestAdapter]:
    return dict(REGISTRY)


__all__ = [
    "REGISTRY",
    "get_adapter",
    "all_adapters",
    "BaseTestAdapter",
    "TestPayload",
    "TestResult",
    "RequestOutcome",
    "Verdict",
]
