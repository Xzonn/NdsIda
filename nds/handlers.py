"""
Generic event handler manager.
"""

import ida_kernwin
import ida_hexrays

import misc

class GenericHandler:
    def install(self):
        return False

class SetupHandlers(ida_kernwin.UI_Hooks):
    _handlers = []
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self._loaded = False

    def _lazy_init(self):
        if not self._loaded:
            if not _manager.hook():
                Exception("Could not setup handler manager")
            self._loaded = True

    def ready_to_run(self):
        if not ida_hexrays.init_hexrays_plugin():
            Exception("HexRays initialization failed")
        
        for handler in self._handlers:
            if not handler.install():
                Exception("Handler initialization failed")
        
        return 0

_manager = SetupHandlers()

def add_handler(handler: GenericHandler):
    _manager._lazy_init()
    _manager._handlers.append(handler)