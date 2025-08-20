"""Simple Module/Request system inspired by Pineapple SDK"""
from __future__ import annotations
import logging
from typing import Callable, Dict, Any, Optional, Tuple

logger = logging.getLogger('pineapple.modules')

class Request:
    def __init__(self, module: str, action: str, **kwargs):
        self.module = module
        self.action = action
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return f"Request(module={self.module}, action={self.action})"

class Module:
    def __init__(self, name: str, log_level: int = logging.WARNING):
        self.name = name
        self._handlers: Dict[str, Callable[[Request], Any]] = {}
        self._on_start = []
        self._on_shutdown = []
        logger.setLevel(log_level)

    def register_action_handler(self, action: str, handler: Callable[[Request], Any]):
        self._handlers[action] = handler

    def handles_action(self, action: str):
        def decorator(fn: Callable[[Request], Any]):
            self.register_action_handler(action, fn)
            return fn
        return decorator

    def register_startup_handler(self, handler: Callable[[], None]):
        self._on_start.append(handler)

    def register_shutdown_handler(self, handler: Callable[[Optional[int]], None]):
        self._on_shutdown.append(handler)

    def on_start(self):
        def decorator(fn: Callable[[], None]):
            self.register_startup_handler(fn)
            return fn
        return decorator

    def on_shutdown(self):
        def decorator(fn: Callable[[Optional[int]], None]):
            self.register_shutdown_handler(fn)
            return fn
        return decorator

    def send_notification(self, message: str, level: int = 0) -> bool:
        # This would integrate with device notifications; here we log
        logger.log(logging.INFO, f"Notification [{level}] {self.name}: {message}")
        return True

    def handle_request(self, request: Request) -> Tuple[Any, bool]:
        handler = self._handlers.get(request.action)
        if not handler:
            return ({'error': 'Unknown action'}, False)
        try:
            res = handler(request)
            # If handler returned tuple (payload, success)
            if isinstance(res, tuple) and len(res) == 2 and isinstance(res[1], bool):
                return (res[0], res[1])
            return (res, True)
        except Exception as e:
            logger.exception('Handler exception')
            return ({'error': str(e)}, False)

    def start(self) -> None:
        """Invoke startup handlers (no args)."""
        for fn in self._on_start:
            try:
                fn()
            except Exception:
                logger.exception('Startup handler exception')

    def shutdown(self, sig: Optional[int] = None) -> None:
        """Invoke shutdown handlers with optional signal."""
        for fn in self._on_shutdown:
            try:
                fn(sig)
            except Exception:
                logger.exception('Shutdown handler exception')
