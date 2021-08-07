from bip.base.bipelt import BipElt
from ...base import CNodeExprIndirectCall, set_cnode_name, set_cnode_type

from bip.hexrays import *

class SmiHandlerRegisterCall(CNodeExprIndirectCall):
    """Represents a call to SmiHandlerRegister()"""

    PROTOTYPE = 'EFI_SMM_INTERRUPT_REGISTER'

    EFI_SMM_HANDLER_ENTRY_POINT2 = BipType.from_c("""EFI_STATUS (f)(
        EFI_HANDLE DispatchHandle,
        void * Context,
        void * CommBuffer,
        UINTN * CommBufferSize)""")

    # Cb stands for Communication Buffer
    COMM_BUFFER_SMI_PREFIX = 'CbSmiHandler'

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
        handler = self.Handler.ignore_cast
        if not isinstance(handler, CNodeExprObj):
            # unexpected
            return

        ea = hex(handler.value)[2:]
        BipElt(handler.value).name = f'{self.COMM_BUFFER_SMI_PREFIX}_{ea}'

        self.EFI_SMM_HANDLER_ENTRY_POINT2.set_at(handler.value)