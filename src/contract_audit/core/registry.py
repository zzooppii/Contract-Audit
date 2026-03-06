"""Plugin registry for analyzers and detectors.

Supports three registration methods:
1. Decorator: @register_detector / @register_analyzer
2. Entry-points: via pyproject.toml [project.entry-points."contract_audit.detectors"]
3. Config: explicit module paths in audit.toml under [plugins]
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
from typing import TYPE_CHECKING, Any, TypeVar

from .exceptions import PluginError

if TYPE_CHECKING:
    from ..analyzers.base import AnalyzerProtocol
    from ..detectors.base import DetectorProtocol

logger = logging.getLogger(__name__)

T = TypeVar("T")

_detector_registry: dict[str, type] = {}
_analyzer_registry: dict[str, type] = {}


def register_detector(cls: type) -> type:
    """Decorator to register a detector class."""
    name = getattr(cls, "name", None) or cls.__name__
    _detector_registry[name] = cls
    logger.debug(f"Registered detector: {name}")
    return cls


def register_analyzer(cls: type) -> type:
    """Decorator to register an analyzer class."""
    name = getattr(cls, "name", None) or cls.__name__
    _analyzer_registry[name] = cls
    logger.debug(f"Registered analyzer: {name}")
    return cls


def _load_entry_points(group: str) -> dict[str, type]:
    """Load plugins from setuptools entry points."""
    plugins: dict[str, type] = {}
    try:
        eps = importlib.metadata.entry_points(group=group)
        for ep in eps:
            try:
                cls = ep.load()
                plugins[ep.name] = cls
                logger.debug(f"Loaded entry-point plugin: {ep.name} from {group}")
            except Exception as e:
                logger.warning(f"Failed to load entry-point {ep.name}: {e}")
    except Exception as e:
        logger.debug(f"No entry points found for {group}: {e}")
    return plugins


def _load_from_module_path(module_path: str) -> type:
    """Load a class from a dotted module path like 'my_pkg.detectors:MyDetector'."""
    if ":" not in module_path:
        raise PluginError(f"Invalid plugin path: {module_path}. Use 'module:ClassName' format.")
    module_str, class_name = module_path.rsplit(":", 1)
    try:
        module = importlib.import_module(module_str)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        raise PluginError(f"Cannot load plugin {module_path}: {e}") from e


class PluginRegistry:
    """Central registry for all analyzers and detectors."""

    def __init__(self) -> None:
        self._detectors: dict[str, type] = {}
        self._analyzers: dict[str, type] = {}

    def discover_all(self, extra_plugin_paths: list[str] | None = None) -> None:
        """Discover all plugins from all sources."""
        # 1. Built-in (decorator-registered)
        self._detectors.update(_detector_registry)
        self._analyzers.update(_analyzer_registry)

        # 2. Entry-points
        self._detectors.update(_load_entry_points("contract_audit.detectors"))
        self._analyzers.update(_load_entry_points("contract_audit.analyzers"))

        # 3. Config-specified module paths
        if extra_plugin_paths:
            for path in extra_plugin_paths:
                try:
                    cls = _load_from_module_path(path)
                    # Determine if it's a detector or analyzer by duck-typing
                    if hasattr(cls, "detect"):
                        name = getattr(cls, "name", path)
                        self._detectors[name] = cls
                    elif hasattr(cls, "analyze"):
                        name = getattr(cls, "name", path)
                        self._analyzers[name] = cls
                    else:
                        logger.warning(f"Plugin {path} has neither detect() nor analyze()")
                except PluginError as e:
                    logger.error(str(e))

        logger.info(
            f"Registry: {len(self._detectors)} detectors, "
            f"{len(self._analyzers)} analyzers loaded"
        )

    def get_detectors(
        self, enabled_names: list[str] | None = None
    ) -> list[Any]:
        """Instantiate and return enabled detectors."""
        instances = []
        for name, cls in self._detectors.items():
            if enabled_names is None or name in enabled_names:
                try:
                    instances.append(cls())
                except Exception as e:
                    logger.error(f"Failed to instantiate detector {name}: {e}")
        return instances

    def get_analyzers(
        self, enabled_names: list[str] | None = None
    ) -> list[Any]:
        """Instantiate and return enabled analyzers."""
        instances = []
        for name, cls in self._analyzers.items():
            if enabled_names is None or name in enabled_names:
                try:
                    instances.append(cls())
                except Exception as e:
                    logger.error(f"Failed to instantiate analyzer {name}: {e}")
        return instances

    @property
    def detector_names(self) -> list[str]:
        return list(self._detectors.keys())

    @property
    def analyzer_names(self) -> list[str]:
        return list(self._analyzers.keys())


# Global registry instance
registry = PluginRegistry()
