from bip.base import *
from bip.hexrays import *
from .. import bip_utils
from . import FunctionMatcher

class SmmIsBufferOutsideSmmValid(FunctionMatcher):

    def __init__(self):
        super().__init__('SmmIsBufferOutsideSmmValid', is_library=True)

    @staticmethod
    def heuristic(f: BipFunction):

        # The prototype of the function must match BOOLEAN (EFI_PHYSICAL_ADDRESS, UINT64).
        if not (f.type.nb_args == 2 and \
                isinstance(f.type.get_arg_type(0), BTypeInt) and \
                isinstance(f.type.get_arg_type(1), BTypeInt) and \
                isinstance(f.type.return_type, (BTypeInt, BTypeBool))):
            return False

        # The function must reference at least one SMRAM descriptor.
        for gSmramDescriptor in BipElt.get_by_prefix('gSmramDescriptor_'):
            if f in gSmramDescriptor.xFuncTo:
                break
        else:
            # No reference to SMRAM descriptor.
            return False

        # Check that all return statements are either 'return TRUE' or 'return FALSE'
        rets = bip_utils.collect_cnode_filterlist(f.hxcfunc, lambda node: True, [CNodeStmtReturn])
        for ret in rets:
            if isinstance(ret.ret_val, CNodeExprNum) and ret.ret_val.value in (0, 1):
                continue
            else:
                return False
        
        # Passed all the tests.
        return True
