"""Module registry — register modules, resolve dependencies, run in order."""

from .base import IngestModule


class ModuleRegistry:
    """Registry of available IngestModules with dependency resolution."""

    def __init__(self):
        self._modules = {}

    def register(self, module):
        """Register an IngestModule instance."""
        if not isinstance(module, IngestModule):
            raise TypeError(f"Expected IngestModule, got {type(module)}")
        if module.name in self._modules:
            raise ValueError(f"Module '{module.name}' already registered")
        self._modules[module.name] = module

    def get(self, name):
        return self._modules.get(name)

    def all(self):
        return list(self._modules.values())

    def resolve_order(self, module_names=None):
        """Topological sort of modules by depends_on.

        Returns list of modules in execution order.
        Raises ValueError on circular dependency.
        """
        names = module_names or list(self._modules.keys())
        sorted_names = []
        visited = set()
        visiting = set()

        def _visit(name):
            if name in visiting:
                raise ValueError(f"Circular dependency involving '{name}'")
            if name in visited:
                return
            visiting.add(name)
            mod = self._modules.get(name)
            if mod:
                for dep in mod.depends_on:
                    if dep in self._modules:
                        _visit(dep)
            visiting.discard(name)
            visited.add(name)
            sorted_names.append(name)

        for n in names:
            if n not in visited:
                _visit(n)

        return [self._modules[n] for n in sorted_names if n in self._modules]


def run_modules(registry, case_id, file_rows, case_context=None, module_names=None, log_cb=None):
    """Run a set of modules in dependency order.

    Args:
        registry: ModuleRegistry instance
        case_id: case UUID
        file_rows: list of file manifest dicts
        case_context: optional dict with case-level metadata
        module_names: list of module names to run (None = all)
        log_cb: optional callback(level, message)

    Returns:
        dict mapping module_name -> {files_processed, artifacts_created, errors}
    """
    if log_cb:
        log_cb("stage", "Module ingest pipeline starting")

    order = registry.resolve_order(module_names)
    results = {}

    for mod in order:
        if log_cb:
            log_cb("info", f"Running module: {mod.name} ({mod.applies_to})")
        try:
            result = mod.run_batch(case_id, file_rows, case_context=case_context, log_cb=log_cb)
            results[mod.name] = result
        except Exception as e:
            if log_cb:
                log_cb("error", f"Module {mod.name} batch failed: {e}")
            results[mod.name] = {"files_processed": 0, "artifacts_created": 0, "errors": 1}

    if log_cb:
        total_arts = sum(r.get("artifacts_created", 0) for r in results.values())
        total_errs = sum(r.get("errors", 0) for r in results.values())
        log_cb("info", f"Ingest complete: {total_arts} artifacts, {total_errs} errors")

    return results
