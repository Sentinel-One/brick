from ...utils.protocol_matcher import ProtocolMatcher
from ...utils.function_matcher import FunctionMatcher
from ..efiXplorer.efiXplorer_module import EfiXplorerModule
from ..postprocessor.uefi.smm.smst import SmiHandlerRegisterCall
from ..base_module import BaseModule
from pathlib import Path
from ...utils import brick_utils

from bip.base import *
from bip.hexrays import *


from .smi import CommBufferSmiHandler, SmiHandler


class SmmBufferValidModule(BaseModule):

    SIGDIR = Path(__file__).parent / 'sig'

    def __init__(self) -> None:
        super().__init__()

    def match_SmmIsBufferOutsideSmmValid(self):

        def _SIBOSV_heuristic(f):

            # The prototype of the function must match BOOLEAN (EFI_PHYSICAL_ADDRESS, UINT64).
            if not (f.type.nb_args == 2 and \
                    isinstance(f.type.get_arg_type(0), BTypeInt) and \
                    isinstance(f.type.get_arg_type(1), BTypeInt) and \
                    isinstance(f.type.return_type, (BTypeInt, BTypeBool))):
                return False

            # The function must reference at least one SMRAM descriptor.
            for gSmramDescriptor in BipElt.get_by_prefix('gSmramDescriptor_'):
                if f in gSmramDescriptor.xFuncTo:
                    return True

            return False

        SIBOSV_recognizer = FunctionMatcher('SmmIsBufferOutsideSmmValid', is_library=True)

        sibosv = SIBOSV_recognizer.match_by_heuristic(_SIBOSV_heuristic)
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
            print(handler)
            if brick_utils.path_exists(handler, SmmIsBufferOutsideSmmValid) or \
               any(brick_utils.path_exists(handler, instance) for instance in instances):
                # Handler uses verification services.
                continue

            if handler.attack_surface:
                self.logger.error(f'SMI {handler.name} does not validate the comm buffer, check for unprotected nested pointers')
                if isinstance(handler, CommBufferSmiHandler):
                    comm_buffer_type = handler.reconstruct_comm_buffer()
                    if self._has_nested_pointers(comm_buffer_type):
                        self.logger.warning(f'SMI {handler.name} has nested pointers in the communication buffer')
                    
