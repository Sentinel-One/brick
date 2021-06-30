import sys
from pathlib import Path
from contextlib import closing
import json

sys.path.append(str(Path(__file__).parents[1]))
from base_module import BaseModule

import ida_loader
import idaapi
from bip.base import *
class EfiXplorerModule(BaseModule):

    EFI_SMM_HANDLER_ENTRY_POINT = BipType.from_c("""EFI_STATUS (f)(
        EFI_HANDLE DispatchHandle,
        void * Context,
        EFI_SMM_SW_CONTEXT * CommBuffer,
        UINTN * CommBufferSize)""")

    DISABLE_UI = 1

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

    @property
    def json_report_path(self):
        return Path(idaapi.get_input_file_path()).with_suffix('.json')

    @property
    def json_report(self):
        with open(self.json_report_path, 'r') as f:
            return json.load(f)

    def set_sw_smi_prototype(self):
        for sw_smi_handler in BipFunction.get_by_prefix("SwSmiHandler"):
            self.logger.debug(f'Applying signature of EFI_SMM_HANDLER_ENTRY_POINT to 0x{sw_smi_handler.ea:x}')
            self.EFI_SMM_HANDLER_ENTRY_POINT.set_at(sw_smi_handler.ea)

    def propagate_vulns(self):
        vulns = self.json_report.get('vulns')
        if not vulns:
            return

        for vuln_name in vulns:
            # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
            addresses = [hex(ea) for ea in self.json_report['vulns'][vuln_name]]
            self.logger.warning(f'efiXplorer: {vuln_name} occuring at {addresses}')


    def _run(self):
        # arg = 1 (01): disable_ui
        ida_loader.load_and_run_plugin(str(self.plugin_path), self.DISABLE_UI)
            
        # Apply correct signature to all SW SMI handlers.
        self.set_sw_smi_prototype()

        ida_loader.flush_buffers()

        # Check if efiXplorer detected any potential vulnerabilities, and if so propagate them.
        self.propagate_vulns()
         
with closing(EfiXplorerModule()) as module:
    module.run()
