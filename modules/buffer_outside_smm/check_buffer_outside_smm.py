from modules import bip_utils
from modules.buffer_outside_smm.FunctionLocator import FunctionRecognizer
import uuid
from ..efiXplorer.apply_efiXplorer import EfiXplorerModule
from ..base_module import BaseModule
from pathlib import Path

from bip.base import *
from bip.hexrays import *

from .. import brick_utils
import modules

class StopCNodeVisit(Exception):
    pass

class SmiHandler(BipFunction):
    
    def __init__(self, ea):
        super().__init__(ea=ea)

    def validate(self):
        if not self.can_decompile:
            return False

        hxcfunc = self.hxcfunc

        # Do some sanity checks on the arguments.
        if not (len(hxcfunc.args) == 4 and \
                hxcfunc.args[0].name == 'DispatchHandle' and \
                hxcfunc.args[1].name == 'Context' and \
                hxcfunc.args[2].name == 'CommBuffer' and \
                hxcfunc.args[3].name == 'CommBufferSize'):
            return False

        return True

    def is_attackable(self):
        pass

class LegacySwSmiHandler(SmiHandler):

    def is_attackable(self):
        if self.can_decompile:

            def callback(cn):

                ea = None 

                if isinstance(cn, CNodeExprCall):
                    if any(x in cn.cstr for x in ('GetVariable', 'SmmGetVariable', 'ReadSaveState')):
                        # Calls one of {GetVariable, SmmGetVariable, ReadSaveState}.
                        ea = cn.ea

                if isinstance(cn, CNodeExprMemptr):
                    if 'CpuSaveState' in cn.cstr:
                        # Reads the SMM save state directly via gSmst->CpuSaveState[CpuIndex].
                        ea = cn.ea
                
                if brick_utils.path_exists(self, ea):
                    raise StopCNodeVisit()

            for hxcfunc in HxCFunc.iter_all():
                try:
                    hxcfunc.visit_cnode_filterlist(callback, [CNodeExprCall, CNodeExprMemptr])
                except StopCNodeVisit:
                    # An 'interesting' element was found via the Hex-Rays pseudocode.
                    return True

        return False


class CommBufferSmiHandler(SmiHandler):

    HANDLER_SIZE_THRESHOLD = 10     # To filter out empty handlers

    def is_attackable(self):
        if self.can_decompile:
            # TODO: Search for xRefs to the arguments.
            hxcfunc = self.hxcfunc
            return hxcfunc.cstr.count('CommBuffer') > 2
        else:
            # Can't decompile for some reason, just make sure it's not a stub.
            return self.size >= self.HANDLER_SIZE_THRESHOLD

class SmmBufferValidModule(BaseModule):

    SIGDIR = Path(__file__).parent / r"sig"
    AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = uuid.UUID('{da473d7f-4b31-4d63-92b7-3d905ef84b84}')

    def __init__(self) -> None:
        super().__init__()
        self.recognizer = FunctionRecognizer('SmmIsBufferOutsideSmmValid')

    @staticmethod
    def _SmmIsBufferOutsideSmmValid_heuristic(f):

        # The function must be decompilable.
        if not f.can_decompile:
            return False

        hxcfunc = f.hxcfunc

        # The prototype of the function must match BOOLEAN (EFI_PHYSICAL_ADDRESS, UINT64).
        if not (len(hxcfunc.args) == 2 and \
                isinstance(hxcfunc.args[0].type, BTypeInt) and \
                isinstance(hxcfunc.args[1].type, BTypeInt) and \
                bip_utils.return_type(hxcfunc).lower() in ('char', 'bool', 'boolean')):
            return False

        # The function must reference at least one SMRAM descriptor.
        for gSmramDescriptor in bip_utils.get_elt_by_prefix('gSmramDescriptor_'):
            if f in gSmramDescriptor.xFuncTo:
                return True

        return False

    def recognize_SmmIsBufferOutsideSmmValid(self):

        self.recognizer.recognize_by_heuristic(self._SmmIsBufferOutsideSmmValid_heuristic)

        if not self.recognizer.get():
            self.recognizer.recognize_by_signature(self.SIGDIR)

        f = self.recognizer.get()
        if f is not None:
            f.is_lib = True

        return f

    def is_interesting_smi_handler(self, f: BipFunction):
        if f.name.startswith('CbSmiHandler'):
            # CommBuffer based SMI.
            smi = CommBufferSmiHandler(f.ea)
        elif f.name.startswith(EfiXplorerModule.LEGACY_SW_SMI_PREFIX):
            # Legacy software SMI.
            smi = LegacySwSmiHandler(f.ea)
        else:
            # Not an SMI.
            return False

        return smi.validate() and smi.is_attackable()

    def _get_interesting_smi_handlers(self):
        interesting_smis = [smi for smi in BipFunction.iter_all() if self.is_interesting_smi_handler(smi)]
        return interesting_smis

    def _locate_AMI_SMM_BUFFER_VALIDATION_PROTOCOL(self):

        def call_node_callback(cn: CNodeExprCall):
            if '->SmmLocateProtocol' in cn.cstr:
                if 'AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID' in cn.get_arg(0).cstr:
                    interface = cn.get_arg(2).ignore_cast
                    if isinstance(interface, CNodeExprRef):
                        # if we have a ref (&global) we want the object under
                        interface = interface.ops[0].ignore_cast
                    if not isinstance(interface, CNodeExprObj):
                        # if this is not a global object we ignore it
                        return
                    ea = interface.value # get the address of the object
                    BipElt(ea).name = 'gAmiSmmBufferValidationProtocol'

        # Some SMM modules use the AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID protocol instead of calling
        # SmmIsBufferOutsideSmmValid directly.
        found = brick_utils.search_guid(self.AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID)
        if found:
            # This protocol is not recognized by efiXplorer, so must rename it manually.
            elt = BipElt(found.ea)
            elt.name = "AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID"

            for cfunc in HxCFunc.iter_all():
                try:
                    cfunc.visit_cnode_filterlist(call_node_callback, [CNodeExprCall])
                except Exception as e:
                    self.logger.debug(e)

            return GetEltByName('gAmiSmmBufferValidationProtocol')

        return None

    def run(self):
        SmmIsBufferOutsideSmmValid = self.recognize_SmmIsBufferOutsideSmmValid()
        gAmiSmmBufferValidationProtocol = self._locate_AMI_SMM_BUFFER_VALIDATION_PROTOCOL()

        for handler in self._get_interesting_smi_handlers():
            if not brick_utils.path_exists(SmmIsBufferOutsideSmmValid, handler) and \
               not brick_utils.path_exists(gAmiSmmBufferValidationProtocol, handler):
                self.res = False
                self.logger.error(f"SMI {handler.name} (0x{handler.ea:x}) doesn't validate the comm buffer, check nested pointers")
            
        if self.res:
            self.logger.success(f"All SMI handlers validate the comm buffer")