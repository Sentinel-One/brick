from ...utils.protocol_matcher import ProtocolMatcher
from ...utils.function_matcher import FunctionMatcher
from ..base_module import BaseModule
from ..efiXplorer.efiXplorer import EfiXplorerModule
from pathlib import Path
from ...utils import brick_utils, bip_utils

from bip.base import *
from bip.hexrays import *


from .smi import CommBufferSmiHandler, LegacySwSmiHandler, SmiHandler


class CheckNestedPointersModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    DEPENDS_ON = [EfiXplorerModule]

    def match_SmmIsBufferOutsideSmmValid(self):

        def _SIBOSV_heuristic(f: BipFunction):

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

        SIBOSV_recognizer = FunctionMatcher('SmmIsBufferOutsideSmmValid', is_library=True)

        sibosv = SIBOSV_recognizer.match_by_heuristic(_SIBOSV_heuristic, decompiler_required=True)
        if sibosv:
            return sibosv

        return None

    @staticmethod
    def _has_nested_pointers(comm_buffer_type):
        '''
        Does the CommBuffer contains nested pointers?
        '''

        # Check if the Comm Buffer has any nested pointers
        return any(isinstance(child, BTypePtr) for child in comm_buffer_type.children[0].children)

    def _scan_comm_buffer_smis(self):

        for handler in CommBufferSmiHandler.iter_all():

            if not handler.CommBuffer._lvar.used:
                # CommBuffer is not used.
                self.logger.verbose(f'SMI {handler.name} does not reference CommBuffer')
                continue

            def _is_smm_validation(node: CNodeExprCall):
                if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                    buffer = node.args[0].ignore_cast
                    
                    if isinstance(buffer, CNodeExprVar) and buffer.lvar == handler.CommBuffer:
                        # Validates the CommBuffer itself.
                        return False

                    # Validates something else. A nested pointer maybe?
                    return True

            # Recursively scan calls made by the handler.
            if bip_utils.search_cnode_filterlist(handler.hxcfunc, _is_smm_validation, [CNodeExprCall], recursive=True):
                self.logger.success(f'SMI {handler.name} seems to validate any pointers nested in the CommBuffer')
                continue

            # The handler does not call SmmIsBufferOutsideSmmValid or equivalent function.
            # Reconstruct the CommBuffer to determine the severity.
            comm_buffer_type = handler.reconstruct_comm_buffer()

            # Check if the Comm Buffer holds any nested pointers
            if any(isinstance(member, BTypePtr) for member in comm_buffer_type.children[0].children):
                self.logger.error(f'SMI {handler.name} does not validate pointers nested in the CommBuffer')
            else:
                self.logger.warning(f'SMI {handler.name} does not validate pointers nested in the CommBuffer')

    def _scan_legacy_sw_smis(self):

        for handler in LegacySwSmiHandler.iter_all():

            if not handler.attack_surface:
                # No attack surface, for example an SMI handler that doesn't call ReadSaveState().
                self.logger.verbose(f'SMI {handler.name} does not expose any attack surface')
                continue

            def _is_smm_validation(node: CNodeExprCall):
                if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                    return True

            # Recursively scan calls made by the handler.
            if bip_utils.search_cnode_filterlist(handler.hxcfunc, _is_smm_validation, [CNodeExprCall], recursive=True):
                self.logger.success(f'SMI {handler.name} seems to validate any externally provided pointers')
                continue

            # Low confidence in the detection, so issue a warning instead of an error.
            self.logger.warning(f'SMI {handler.name} does not validate externally provided pointers')

    def run(self):
        SmmIsBufferOutsideSmmValid = self.match_SmmIsBufferOutsideSmmValid()
        
        self._scan_comm_buffer_smis()
        self._scan_legacy_sw_smis()
        