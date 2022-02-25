from ...base import CNodeExprIndirectCall
from .....efiXplorer.efiXplorer import EfiXplorerPlugin

from bip.base import *
from bip.hexrays import *

import logging

class SmiHandlerRegisterCall(CNodeExprIndirectCall):
    """Represents a call to SmiHandlerRegister()"""

    PROTOTYPE = 'EFI_SMM_INTERRUPT_REGISTER'

    @property
    def Handler(self):
        return self.get_arg(0)

    @property
    def HandlerType(self):
        return self.get_arg(1)

    @property
    def DispatchHandle(self):
        return self.get_arg(2)

    def process(self):
        pass
    
        # handler = self.Handler.ignore_cast
        # if not isinstance(handler, CNodeExprObj):
        #     # unexpected
        #     return

        # ea = hex(handler.value)[2:]
        # BipElt(handler.value).name = f'{self.COMM_BUFFER_SMI_PREFIX}_{ea}'

        # self.EFI_SMM_HANDLER_ENTRY_POINT2.set_at(handler.value)