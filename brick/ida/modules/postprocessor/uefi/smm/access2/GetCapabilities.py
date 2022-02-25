from ...base import CNodeExprIndirectCall

from bip.base import *
from bip.hexrays import *

import logging

class GetCapabilitiesCall(CNodeExprIndirectCall):
    """"Represents a call to GetCapabilities()"""
    
    PROTOTYPE = 'EFI_SMM_CAPABILITIES2'

    SMRAM_DESCRIPTOR_PREFIX = 'gSmramDescriptor_'

    @property
    def This(self):
        return self.get_arg(0)

    @property
    def SmramMapSize(self):
        return self.get_arg(1)

    @property
    def SmramMap(self):
        return self.get_arg(2)

    def process(self):
        smram_descriptor = self.SmramMap.ignore_cast
        if isinstance(smram_descriptor, CNodeExprRef):
            # if we have a ref (&global) we want the object under
            smram_descriptor = smram_descriptor.ops[0].ignore_cast
        if not isinstance(smram_descriptor, CNodeExprObj):
            # if this is not a global object we ignore it
            return
        ea = smram_descriptor.value # get the address of the object

        # Apply correct type
        BipType.from_c('EFI_SMRAM_DESCRIPTOR *').set_at(ea)
        # Rename to allow for easy reference in the future
        BipElt(ea).name = f'{self.SMRAM_DESCRIPTOR_PREFIX}_{ea:x}'

        logging.getLogger('brick').debug(f'Discovered an EFI_SMRAM_DESCRIPTOR at 0x{ea:x}')