from bip.base import *
from bip.hexrays import *
from brick.ida.modules.postprocessor.uefi.smm import access2
from .. import bip_utils
from . import FunctionMatcher

from ...modules.postprocessor.uefi.smm.access2.GetCapabilities import GetCapabilitiesCall

class SmmIsBufferOutsideSmmValid(FunctionMatcher):

    def __init__(self):
        super().__init__('SmmIsBufferOutsideSmmValid', is_library=True, decompiler_required=True)

    @staticmethod
    def check_args(f: BipFunction):
        # The arguments of the function must match (EFI_PHYSICAL_ADDRESS Buffer, UINT64 Length).
        if (f.type.nb_args == 2 and \
            isinstance(f.type.get_arg_type(0), BTypeInt) and \
            isinstance(f.type.get_arg_type(1), BTypeInt)):
            return True
        else:
            return False

    @staticmethod
    def check_retval(f: BipFunction):
        if not isinstance(f.type.return_type, (BTypeInt, BTypeBool)):
            # Return value is definitely not a bool. 
            return False

        # Check that all return statements are either 'return TRUE' or 'return FALSE'
        def inspect_return(node: CNodeStmtReturn):
            if not isinstance(node.ret_val, CNodeExprNum) or node.ret_val.value not in (0, 1):
                # Singal the search to stop.
                return False

        # Visit all the return statements in the function.
        return not f.hxcfunc.visit_cnode_filterlist(inspect_return, [CNodeStmtReturn])

    @staticmethod
    def references_smram_descriptor(f: BipFunction):
        # The function must reference at least one SMRAM descriptor.
        for SmramDescriptor in BipElt.get_by_prefix(GetCapabilitiesCall.SMRAM_DESCRIPTOR_PREFIX):
            if f in SmramDescriptor.xFuncTo:
                return True
        else:
            # No reference to SMRAM descriptor.
            return False

    @staticmethod
    def heuristic(f: BipFunction):
        return SmmIsBufferOutsideSmmValid.check_args(f) and \
               SmmIsBufferOutsideSmmValid.check_retval(f) and \
               SmmIsBufferOutsideSmmValid.references_smram_descriptor(f)
