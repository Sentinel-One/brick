from ..base import CNodeExprIndirectCall

class SetVariableCall(CNodeExprIndirectCall):
    """"Represents a call to SetVariable()"""
    
    PROTOTYPE = 'EFI_SET_VARIABLE'

    @property
    def VariableName(self):
        return self.get_arg(0)

    @property
    def VendorGuid(self):
        return self.get_arg(1)

    @property
    def Attributes(self):
        return self.get_arg(2)

    @property
    def DataSize(self):
        return self.get_arg(3)

    @property
    def Data(self):
        return self.get_arg(4)
