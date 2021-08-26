from bip.base.biptype import BipType
from ...base import CNodeExprIndirectCall, set_cnode_name, set_cnode_type

from bip.base import *
from bip.hexrays import *

class GetCapabilitiesCall(CNodeExprIndirectCall):
    """"Represents a call to GetCapabilities()"""
    
    PROTOTYPE = 'EFI_SMM_CAPABILITIES2'

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
            # print(f'smram descriptor is of type {type(smram_descriptor)}')
            return
        # print(f'renaming at {smram_descriptor}')
        ea = smram_descriptor.value # get the address of the object
        BipElt(ea).name = 'gSmramDescriptor_' + hex(ea)[2:]

        set_cnode_type(smram_descriptor, BipType.from_c('EFI_SMRAM_DESCRIPTOR *'))
