from ..base import UefiCall

class SetVariableCall(UefiCall):
    """"Represents a call to SetVariable()"""
    
    PROTOTYPE = 'EFI_SET_VARIABLE'

    @property
    def VariableName(self):
        pass

    @property
    def VendorGuid(self):
        pass

    @property
    def Attributes(self):
        pass

    @property
    def DataSize(self):
        pass

    @property
    def Data(self):
        pass
