from bip.base import *
from bip.hexrays import *
from .. import bip_utils
from . import FunctionMatcher

class FreePool(FunctionMatcher):
    '''
    See https://github.com/tianocore/edk2/blob/master/MdePkg/Library/SmmMemoryAllocationLib/MemoryAllocationLib.c
    '''

    def __init__(self):
        super().__init__('FreePool', is_library=True)

    @staticmethod
    def heuristic(f: BipFunction):
        # The prototype of the function must match EFI_STATUS (void *).
        if not (f.type.nb_args == 1 and \
                isinstance(f.type.get_arg_type(0), (BTypePtr, BTypeInt)) and \
                isinstance(f.type.return_type, (BTypeInt))):
            return False

        # Collect all the calls used to free pool memory.
        def is_smm_free_pool(node: CNodeExprCall):
            return '->SmmFreePool' in node.cstr
        def is_bs_free_pool(node: CNodeExprCall):
            return '->FreePool' in node.cstr

        smm_free_pool = bip_utils.collect_cnode_filterlist(f.hxcfunc, is_smm_free_pool, [CNodeExprCall])
        bs_free_pool = bip_utils.collect_cnode_filterlist(f.hxcfunc, is_bs_free_pool, [CNodeExprCall])

        # Each of these functions should be called EXACLY once.
        if len(smm_free_pool) != 1 or len(bs_free_pool) != 1:
            return False

        # The same pointer should be forwarded to both functions.
        if smm_free_pool[0].args[0].ignore_cast.lvar != f.hxcfunc.args[0] or \
            bs_free_pool[0].args[0].ignore_cast.lvar != f.hxcfunc.args[0]:
            return False
        
        # All tests passed.
        return True