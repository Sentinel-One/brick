from ...base import CNodeExprIndirectCall

class WriteSaveStateCall(CNodeExprIndirectCall):
    """Represents a call to WriteSaveState()"""
    
    PROTOTYPE = 'EFI_SMM_WRITE_SAVE_STATE'

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
        pass