from pathlib import Path
import json
import uuid

from ..base_module import BaseModule
from .. import brick_utils

import ida_loader
import idaapi
import ida_segment
import idc
from bip.base import *
from bip.hexrays import *
class EfiXplorerModule(BaseModule):

    EFI_SMM_HANDLER_ENTRY_POINT = BipType.from_c("""EFI_STATUS (f)(
        EFI_HANDLE DispatchHandle,
        void * Context,
        EFI_SMM_SW_CONTEXT * CommBuffer,
        UINTN * CommBufferSize)""")

    # arg = 1 (01): disable_ui
    DISABLE_UI = 1

    EFI_SMM_RUNTIME_SERVICES_TABLE_GUID = uuid.UUID('{395C33FE-287F-413E-A055-8088C0E1D43E}')

    @property
    def plugin_path(self):
        parent_dir = Path(__file__).parent

        inf_struct = idaapi.get_inf_structure()
        if inf_struct.is_64bit():
            _plugin_path = parent_dir / 'efiXplorer64.dll'
        elif inf_struct.is_32bit():
            _plugin_path = parent_dir / 'efiXplorer.dll'
        else:
            _plugin_path = None

        return _plugin_path

    @staticmethod
    def json_report() -> dict:
        json_report_path = Path(idaapi.get_input_file_path()).with_suffix('.json')
        with open(json_report_path, 'r') as f:
            return json.load(f)

    def fix_sw_smis_signatures(self):
        for sw_smi_handler in BipFunction.get_by_prefix("SwSmiHandler"):
            self.EFI_SMM_HANDLER_ENTRY_POINT.set_at(sw_smi_handler.ea)

    def set_text_section_rwx(self):
        text_section = ida_segment.get_segm_by_name('.text')
        if text_section:
            idc.set_segm_attr(text_section.start_ea, idc.SEGATTR_PERM, idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_EXEC)

    def find_missing_functions(self):
        """
        Use codatify to find functions that the initial auto-analysis missed.
        """
        try:
            import codatify
            codatify.fix_code()
        except ImportError:
            pass

        # Codatify sometimes does one of the following:
        # 1. Prepend int 3 instructions to the start of the function.
        # 2. Assemble a bunch of int 3 opcodes into their own function.
        # We attempt to fix these issues by re-creating some of the functions.
        for f in BipFunction.iter_all():
            new_ea = f.ea
            while new_ea < f.end and BipInstr(new_ea).bytes == [0xCC]: # int 3
                # Counts the number of int 3
                new_ea += 1
            
            if new_ea != f.ea:
                if new_ea == f.end:
                    # Delete 'functions' comprising entirely out of int 3 instructions.
                    idc.del_func(f.ea)
                else:
                    # Re-create functions 
                    idc.del_func(f.ea)
                    BipFunction.create(new_ea)

    def propagate_vulns(self):
        vulns = self.json_report().get('vulns', [])
        if vulns:
            self.res = False

        for vuln_name in vulns:
            # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
            addresses = [hex(ea) for ea in self.json_report()['vulns'][vuln_name]]
            self.logger.warning(f'{vuln_name} occuring at {addresses}')

            if vuln_name == 'smm_callout':
                if brick_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
                    self.logger.info('Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs likely to be false positive')
                else:
                    self.logger.warning('Module does not reference EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs might be true positives')
        
        if self.res:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")

    def preprocess(self):
        # Fix permissions for the code section
        self.set_text_section_rwx()
        # Find functions that the initial auto-analysis might have missed.
        self.find_missing_functions()

    @staticmethod
    def _handle_read_save_state_call(cn):
        brick_utils.set_indirect_call_type(cn.ea, 'EFI_SMM_READ_SAVE_STATE')
        cn.hxcfunc.invalidate_cache()
        
        reg = cn.get_arg(2)
        reg_name = reg.cstr.split('_')[5].lower()   # e.g. EFI_SMM_SAVE_STATE_REGISTER_RCX

        buffer = cn.get_arg(4)
        if isinstance(buffer, CNodeExprRef):
            # if we have a ref (&something) we want the object under
            buffer = buffer.ops[0].ignore_cast
        if isinstance(buffer, CNodeExprVar):
            buffer.lvar.name = 'v_' + reg_name


    @staticmethod
    def _handle_write_save_state_call(cn):
        pass

    @staticmethod
    def _handle_get_variable_call(cn):
        pass

    @staticmethod
    def _handle_set_variable_call(cn):
        pass

    def fix_efi_services_signatures(self):

        EFI_SERVICES_PROTOTYPES = {
            'ReadSaveState': 'EFI_SMM_READ_SAVE_STATE',
            'WriteSaveState': 'EFI_SMM_WRITE_SAVE_STATE',
            'GetVariable': 'EFI_GET_VARIABLE',
            'SmmGetVariable': 'EFI_GET_VARIABLE',
            'SetVariable': 'EFI_SET_VARIABLE',
            'SmmSetVariable': 'EFI_SET_VARIABLE',
        }

        def callback(cn: CNodeExprCall):
            for service, prototype in EFI_SERVICES_PROTOTYPES.items():
                if '->' + service in cn.cstr:
                    brick_utils.set_indirect_call_type(cn.ea, prototype)
                    cn.hxcfunc.invalidate_cache()

        for f in BipFunction.iter_all():
            try:
                cfunc = HxCFunc.from_addr(f.ea)
                cfunc.visit_cnode_filterlist(callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e)

    def rename_efi_services_arguments(self):

        EFI_SERVICES_HANDLERS = {
            'ReadSaveState': EfiXplorerModule._handle_read_save_state_call,
            'WriteSaveState': EfiXplorerModule._handle_write_save_state_call,
            'GetVariable': EfiXplorerModule._handle_get_variable_call,
            'SmmGetVariable': EfiXplorerModule._handle_get_variable_call,
            'SetVariable': EfiXplorerModule._handle_set_variable_call,
            'SmmSetVariable': EfiXplorerModule._handle_set_variable_call,
        }

        def callback(cn: CNodeExprCall):
            for service, handler in EFI_SERVICES_HANDLERS.items():
                if '->' + service in cn.cstr:
                    handler(cn)
                    cn.hxcfunc.invalidate_cache()

        for f in BipFunction.iter_all():
            try:
                cfunc = HxCFunc.from_addr(f.ea)
                cfunc.visit_cnode_filterlist(callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e)

    def postprocess(self):
        # Apply correct signature to all SW SMI handlers.
        self.fix_sw_smis_signatures()
        # Fix signatures for common EFI/SMM services that efiXplorer missed.
        self.fix_efi_services_signatures()
        self.rename_efi_services_arguments()

    def run(self):
        self.preprocess()

        ida_loader.load_and_run_plugin(str(self.plugin_path), self.DISABLE_UI)
        
        self.postprocess()

        # Check if efiXplorer detected any potential vulnerabilities, and if so propagate them.
        self.propagate_vulns()
         
