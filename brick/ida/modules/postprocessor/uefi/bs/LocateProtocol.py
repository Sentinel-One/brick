from ..base import CNodeExprIndirectCall

from bip.base import *
from bip.hexrays import *

class LocateProtocolCall(CNodeExprIndirectCall):
    """Represents a call to LocateProtocol()"""

    PROTOTYPE = 'EFI_LOCATE_PROTOCOL'

    @property
    def Protocol(self):
        return self.get_arg(0)

    @property
    def Registration(self):
        return self.get_arg(1)

    @property
    def Interface(self):
        return self.get_arg(2)

    def process(self):
        # Recent version of efiXplorer already take care of assigning the correct type to the
        # interface pointer.
        pass
