from ...utils.protocol_recognizer import ProtocolRecognizer
from ...utils.function_locator import FunctionRecognizer
from ..efiXplorer.apply_efiXplorer import EfiXplorerModule
from ..postprocessor.uefi.smm.smst import SmiHandlerRegisterCall
from ..base_module import BaseModule
from pathlib import Path

from bip.base import *
from bip.hexrays import *


from .smi import LegacySwSmiHandler, CommBufferSmiHandler, SmiHandler


class SmmBufferValidModule(BaseModule):

    SIGDIR = Path(__file__).parent / r"sig"

    def __init__(self) -> None:
        super().__init__()

    def recognize_SIBOSV(self):

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

        SIBOSV_recognizer = FunctionRecognizer('SmmIsBufferOutsideSmmValid', is_library=True)

        sibosv = SIBOSV_recognizer.recognize_by_heuristic(_SIBOSV_heuristic)
        if sibosv:
            return sibosv

        sibosv = SIBOSV_recognizer.recognize_by_diaphora(r"C:\Users\carlsbad\Work\firmware\hp\SmmLockBox.efi.sqlite", 0.75)
        if sibosv:
            return sibosv

        sibosv = SIBOSV_recognizer.recognize_by_rizzo(self.SIGDIR)
        if sibosv:
            return sibosv

        return None



    def recognize_AMI_SMM_BUFFER_VALIDATION_PROTOCOL(self):

        AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = '{da473d7f-4b31-4d63-92b7-3d905ef84b84}'

        # Some SMM modules use the AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID protocol instead of calling
        # SmmIsBufferOutsideSmmValid directly.
        ASBVP_recognizer = ProtocolRecognizer(AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID, 'AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID', is_smm=True)
        ASBVP_recognizer.recognize()
        # For now just returns the 1st instance.
        # return ASBVP_recognizer.get().Instances[0]

    def run(self):
        self.recognize_SIBOSV()
        self.recognize_AMI_SMM_BUFFER_VALIDATION_PROTOCOL()
        # print(gAmiSmmBufferValidationProtocol)

        res = SmiHandler.ValidationResult.NO_SMIS

        for handler in SmiHandler.iter_all():
            res = handler.validate()
            
            if res & SmiHandler.ValidationResult.NO_ATTACK_SURFACE:
                self.logger.info(f'SMI {handler.name} does not expose any attack surface')

            if res & SmiHandler.ValidationResult.CHECK_NESTED_POINTERS:
                self.logger.error(f'SMI {handler.name} does not validate the comm buffer, check for unprotected nested pointers')

            if res & SmiHandler.ValidationResult.HAS_NESTED_POINTERS:
                self.logger.warning(f'SMI {handler.name} has pointers nested in the comm buffer')
                
            if res & SmiHandler.ValidationResult.CHECK_POTENTIAL_OVERFLOW:
                self.logger.error(f'SMI {handler.name} does not check the size of the comm buffer, check for potential overflows')

            if res == SmiHandler.ValidationResult.SUCCESS:
                self.logger.success(f'SMI {handler.name} seems secure')
            
        if res == SmiHandler.ValidationResult.NO_SMIS:
            self.logger.success(f'No software SMIs found')