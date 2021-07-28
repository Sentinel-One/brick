from bip.base import *
from bip.hexrays import *

from .uefi.factory import factory
from .. import brick_utils
from ..base_module import BaseModule

class PostprocessorModule(BaseModule):

    EFI_SMM_HANDLER_ENTRY_POINT = BipType.from_c("""EFI_STATUS (f)(
        EFI_HANDLE DispatchHandle,
        void * Context,
        EFI_SMM_SW_CONTEXT * CommBuffer,
        UINTN * CommBufferSize)""")

    def _fix_sw_smis_signatures(self):
        for sw_smi_handler in BipFunction.get_by_prefix("SwSmiHandler"):
            self.EFI_SMM_HANDLER_ENTRY_POINT.set_at(sw_smi_handler.ea)

    def _fix_efi_services_signatures(self):

        def set_call_type_callback(cn: CNodeExprCall):
            x = factory.get_call(cn)
            if x is not None:
                x.set_call_type()

        for cfunc in HxCFunc.iter_all():
            try:
                cfunc.visit_cnode_filterlist(set_call_type_callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e)

    def _rename_efi_services_arguments(self):

        def callback(cn: CNodeExprCall):
            x = factory.get_call(cn)
            if x is None:
                return
            
            x.process()
            cn.hxcfunc.invalidate_cache()

        for cfunc in HxCFunc.iter_all():
            try:
                cfunc.visit_cnode_filterlist(callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e)
    
    def run(self):
        # Apply correct signature to all SW SMI handlers.
        self._fix_sw_smis_signatures()
        # Fix signatures for common EFI/SMM services that efiXplorer missed.
        self._fix_efi_services_signatures()
        # Rename some arguments accordingly.
        self._rename_efi_services_arguments()