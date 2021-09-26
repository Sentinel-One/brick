from ...utils.protocol_matcher import ProtocolMatcher
from ...utils.function_matcher import FunctionMatcher
from ..efiXplorer.efiXplorer_module import EfiXplorerModule
from ..postprocessor.uefi.smm.smst import SmiHandlerRegisterCall
from ..base_module import BaseModule
from pathlib import Path
from ...utils import brick_utils, bip_utils

from bip.base import *
from bip.hexrays import *


from .smi import CommBufferSmiHandler, SmiHandler


class CheckNestedPointersModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

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

        # We know that SmmLockBox contains multiple calls to SmmIsBufferOutsideSmmValid()
        smm_lock_box_database = str(Path(__file__).parent / 'SmmLockBox.efi.sqlite')
        sibosv = SIBOSV_recognizer.match_by_diaphora(smm_lock_box_database, 0.75)
        if sibosv:
            return sibosv

        return None

    def match_AMI_SMM_BUFFER_VALIDATION_PROTOCOL(self):

        AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = '{da473d7f-4b31-4d63-92b7-3d905ef84b84}'

        # Some SMM modules use the AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID protocol instead of calling
        # SmmIsBufferOutsideSmmValid directly.
        ASBVP_matcher = ProtocolMatcher(AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID, 'AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID', is_smm=True)
        ASBVP_matcher.match()
        return ASBVP_matcher.get()
        # For now just returns the 1st instance.
        # return ASBVP_recognizer.get().Instances[0]

    @staticmethod
    def _has_nested_pointers(comm_buffer_type):
        '''
        Does the CommBuffer contains nested pointers?
        '''

        # Check if the Comm Buffer has any nested pointers
        return any(isinstance(child, BTypePtr) for child in comm_buffer_type.children[0].children)

    def run(self):
        SmmIsBufferOutsideSmmValid = self.match_SmmIsBufferOutsideSmmValid()
        (_, instances) = self.match_AMI_SMM_BUFFER_VALIDATION_PROTOCOL()

        for handler in SmiHandler.iter_all():
            if not handler.attack_surface:
                self.logger.verbose(f'SMI {handler.name} does not expose any attack surface')
                continue

            if brick_utils.path_exists(handler, SmmIsBufferOutsideSmmValid) or \
               any(brick_utils.path_exists(handler, instance) for instance in instances):
                # Handler uses verification services.
                self.logger.verbose(f'SMI {handler.name} seems secure')
                continue

            self.logger.error(f'SMI {handler.name} does not validate the comm buffer, check for unprotected nested pointers')
            if isinstance(handler, CommBufferSmiHandler):
                comm_buffer_type = handler.reconstruct_comm_buffer()
                if self._has_nested_pointers(comm_buffer_type):
                    self.logger.warning(f'SMI {handler.name} has nested pointers in the communication buffer')
                    
