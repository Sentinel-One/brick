from ...base import CNodeExprIndirectCall

from bip.base import *
from bip.hexrays import *


class ValidateMemoryBufferCall(CNodeExprIndirectCall):
    """Represents a call to ValidateMemoryBuffer()"""

    PROTOTYPE = 'AMI_SMM_VALIDATE_MEMORY_BUFFER'

    @property
    def Buffer(self):
        return self.get_arg(0)

    @property
    def BufferSize(self):
        return self.get_arg(1)

class ValidateMmioBufferCall(CNodeExprIndirectCall):
    """Represents a call to ValidateMmioBuffer()"""

    PROTOTYPE = 'AMI_SMM_VALIDATE_MMIO_BUFFER'

    @property
    def Buffer(self):
        return self.get_arg(0)

    @property
    def BufferSize(self):
        return self.get_arg(1)

class ValidateSmramBufferCall(CNodeExprIndirectCall):
    """Represents a call to ValidateSmramBuffer()"""

    PROTOTYPE = 'AMI_SMM_VALIDATE_SMRAM_BUFFER'

    @property
    def Buffer(self):
        return self.get_arg(0)

    @property
    def BufferSize(self):
        return self.get_arg(1)
