from ..base import UefiCall, set_cnode_name, set_cnode_type

from bip.hexrays import *

class ReadSaveStateCall(UefiCall):
    """Represents a call to ReadSaveState()"""

    PROTOTYPE = 'EFI_SMM_READ_SAVE_STATE'

    @property
    def This(self):
        return self.get_arg(0)

    @property
    def Width(self):
        return self.get_arg(1)

    @property
    def Register(self):
        return self.get_arg(2)

    @property
    def CpuIndex(self):
        return self.get_arg(3)

    @property
    def Buffer(self):
        return self.get_arg(4)

    def process(self):
        register = self.Register.ignore_cast
        if not isinstance(register, CNodeExprNum):
            # Register is not a literal.
            return

        # TODO: Take into account the Width parameter.
        register_name = self.Register.cstr.split('_')[5].lower()   # e.g. EFI_SMM_SAVE_STATE_REGISTER_RCX

        buffer = self.Buffer

        set_cnode_name(buffer, register_name)