from modules.postprocessor.uefi.LocateProtocol import LocateProtocolCall
from .ReadSaveState import ReadSaveStateCall
from .WriteSaveState import WriteSaveStateCall
from .GetVariable import GetVariableCall
from .SetVariable import SetVariableCall

class UefiCallFactory:

    def __init__(self) -> None:
        self._creators = {}

    def register(self, name, cls):
        self._creators[name] = cls

    def get_call(self, cnode):
        for name, cls in self._creators.items():
            if '->' + name in cnode.cstr:
                return cls.from_cnode(cnode)

UEFI_SERVICE_CALLS = {
    'ReadSaveState':        ReadSaveStateCall,
    # 'WriteSaveState':       WriteSaveStateCall,
    # 'GetVariable':          GetVariableCall,
    # 'SmmGetVariable':       GetVariableCall,
    # 'SetVariable':          SetVariableCall,
    # 'SmmSetVariable':       SetVariableCall,
    'LocateProtocol':       LocateProtocolCall,
    'SmmLocateProtocol':    LocateProtocolCall,
}

factory = UefiCallFactory()
for name, cls in UEFI_SERVICE_CALLS.items():
    factory.register(name, cls)