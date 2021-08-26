from ...base import CNodeExprIndirectCall

class WriteSaveStateCall(CNodeExprIndirectCall):
    """Represents a call to WriteSaveState()"""
    
    PROTOTYPE = 'EFI_SMM_WRITE_SAVE_STATE'