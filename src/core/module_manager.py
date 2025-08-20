"""ModuleManager: registra módulos y despacha Requests."""
from __future__ import annotations
from typing import Dict, Tuple, Any, Optional
from .modules import Module, Request

class ModuleManager:
    def __init__(self) -> None:
        self._modules: Dict[str, Module] = {}

    def register(self, module: Module) -> None:
        self._modules[module.name] = module

    def get(self, name: str) -> Optional[Module]:
        return self._modules.get(name)

    def handle(self, request: Request) -> Tuple[Any, bool]:
        mod = self.get(request.module)
        if not mod:
            return ({'error': f'Unknown module: {request.module}'}, False)
        return mod.handle_request(request)

_default_manager: Optional[ModuleManager] = None

def get_default_manager() -> ModuleManager:
    """Crea un manager singleton y registra módulos base."""
    global _default_manager
    if _default_manager is None:
        _default_manager = ModuleManager()
        # Import tardío para no crear bucles de import
        from .pineapple_module import module as pineapple_module
        _default_manager.register(pineapple_module)
    return _default_manager