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
        EFI_SMM_HANDLER_ENTRY_POINT2 = BipType.from_c("""EFI_STATUS (f)(
            EFI_HANDLE DispatchHandle,
            void * Context,
            void * CommBuffer,
            UINTN * CommBufferSize)""")

        handler = self.Handler.ignore_cast
        if not isinstance(handler, CNodeExprObj):
            # Unexpected
            return

        # Force the type of the handler.
        EFI_SMM_HANDLER_ENTRY_POINT2.set_at(handler.value)

        if BipElt(handler.value).name.startswith(EfiXplorerPlugin.CB_SMI_PREFIX):
            # SMI handler that is already identified.
            return

        # SMI handler that efiXplorer missed.
        BipElt(handler.value).name = f'{EfiXplorerPlugin.CB_SMI_PREFIX}_{handler.value:x}'
        logging.getLogger('brick').info(f'Discovered an SMI handler at 0x{handler.value:x}')
        
class SmiHandlerUnRegisterCall(CNodeExprIndirectCall):
    """Represents a call to SmiHandlerUnRegister()"""

    PROTOTYPE = 'EFI_SMM_INTERRUPT_UNREGISTER'

    @property
    def DispatchHandle(self):
        return self.get_arg(0)

    def process(self):
        pass
    