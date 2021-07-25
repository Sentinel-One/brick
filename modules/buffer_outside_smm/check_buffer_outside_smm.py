import uuid
from ..efiXplorer.apply_efiXplorer import EfiXplorerModule
from ..base_module import BaseModule
from pathlib import Path

import os

import rizzo

from bip.base import *
from bip.hexrays import *

from .. import brick_utils

class StopCNodeVisit(Exception):
    pass

class SmmBufferValidModule(BaseModule):

    SIGDIR = Path(__file__).parent / r"sig"
    AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = uuid.UUID('{da473d7f-4b31-4d63-92b7-3d905ef84b84}')
    HANDLER_SIZE_THRESHOLD = 10     # To filter out empty handlers

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def _get_SmmIsBufferOutsideSmmValid(sigdir):
        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

        # Check if we have a match.
        return BipFunction.get_by_name("SmmIsBufferOutsideSmmValid")

    @staticmethod
    def _get_smi_handlers() -> list:
        # Legacy SW SMIs + CommBuffer SMIs
        return BipFunction.get_by_prefix("SwSmiHandler") + BipFunction.get_by_prefix("Handler")

    def read_save_state_calls(self):
        return EfiXplorerModule.json_report().get('ReadSaveState', [])

    def get_variable_calls(self):
        rt_all = EfiXplorerModule.json_report().get('rt_all')
        if rt_all is not None:
            return rt_all.get('GetVariable', [])
        else:
            return []

    def _is_interesting_comm_buffer_smi(self, f: BipFunction):
        if f.can_decompile:
            cfunc = HxCFunc.from_addr(f.ea)
            # Do some sanity checks on the arguments.
            if len(cfunc.args) != 4 or cfunc.args[2].name != 'CommBuffer' or cfunc.args[3].name != 'CommBufferSize':
                return False
            
            # TODO: Search for xRefs to the arguments.
            return cfunc.cstr.count('CommBuffer') > 2
        else:
            # Can't decompile for some reason, just make sure it's not a stub.
            return f.size >= self.HANDLER_SIZE_THRESHOLD

    def _is_interesting_legacy_smi(self, f: BipFunction):
        for rss in self.read_save_state_calls():
            if brick_utils.path_exists(f, rss):
                # The SMI handler calls ReadSaveState().
                return True

        for gv in self.get_variable_calls():
            if brick_utils.path_exists(f, gv):
                # The SMI handler calls GetVariable().
                return True

        if f.can_decompile:

            def callback(cn):
                if isinstance(cn, CNodeExprCall):
                    if any(x in cn.cstr for x in ('GetVariable', 'SmmGetVariable', 'ReadSaveState')):
                        # Calls one of {GetVariable, SmmGetVariable, ReadSaveState}.
                        raise StopCNodeVisit()

                if isinstance(cn, CNodeExprMemptr):
                    if 'CpuSaveState' in cn.cstr:
                        # Reads the SMM save state directly via gSmst->CpuSaveState[CpuIndex].
                        raise StopCNodeVisit()

            cfunc = HxCFunc.from_addr(f.ea)
            try:
                cfunc.visit_cnode_filterlist(callback, [CNodeExprCall, CNodeExprMemptr])
            except StopCNodeVisit:
                # An 'interesting' element was found via the Hex-Rays pseudocode.
                return True

        return False

    def is_interesting_smi_handler(self, f: BipFunction):
        if f.name.startswith('Handler'):
            # CommBuffer based SMI.
            return self._is_interesting_comm_buffer_smi(f)

        if f.name.startswith('SwSmiHandler'):
            # Legacy software SMI.
            return self._is_interesting_legacy_smi(f)

    def _get_interesting_smi_handlers(self):
        all_smis = self._get_smi_handlers()
        interesting_smis = (smi for smi in all_smis if self.is_interesting_smi_handler(smi))
        return interesting_smis

    def _get_ami_smm_buffer_validation_protocol(self):

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

            for func in BipFunction.iter_all():
                try:
                    cfunc = HxCFunc.from_addr(func.ea)
                    cfunc.visit_cnode_filterlist(call_node_callback, [CNodeExprCall])
                except Exception as e:
                    self.logger.debug(e)

            return GetEltByName('gAmiSmmBufferValidationProtocol')

        return None

    def run(self):
        SmmIsBufferOutsideSmmValid = self._get_SmmIsBufferOutsideSmmValid(self.SIGDIR)
        gAmiSmmBufferValidationProtocol = self._get_ami_smm_buffer_validation_protocol()

        for handler in self._get_interesting_smi_handlers():
            if not brick_utils.path_exists(SmmIsBufferOutsideSmmValid, handler) and \
               not brick_utils.path_exists(gAmiSmmBufferValidationProtocol, handler):
                self.res = False
                self.logger.error(f"SMI {handler.name} (0x{handler.ea:x}) doesn't validate the comm buffer, check nested pointers")
            
        if self.res:
            self.logger.success(f"All SMI handlers validate the comm buffer")