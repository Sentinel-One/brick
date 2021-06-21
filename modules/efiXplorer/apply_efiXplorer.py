import sys
from pathlib import Path
from contextlib import closing
import json

sys.path.append(str(Path(__file__).parents[1]))
from base_module import BaseModule

import ida_loader
import idaapi
from bip.base import *

EFI_SMM_HANDLER_ENTRY_POINT = BipType.from_c("""EFI_STATUS (f)(
    EFI_HANDLE DispatchHandle,
    void * Context,
    EFI_SMM_SW_CONTEXT * CommBuffer,
    UINTN * CommBufferSize)""")

class EfiXplorerModule(BaseModule):

    def _run(self):
        parent_dir = Path(__file__).parent

        inf = idaapi.get_inf_structure()
        if inf.is_64bit():
            plugin_path = parent_dir / 'efiXplorer64.dll'
        elif inf.is_32bit():
            plugin_path = parent_dir / 'efiXplorer.dll'
        else:
            plugin_path = None

        if plugin_path:
            # arg = 1 (01): disable_ui
            ida_loader.load_and_run_plugin(str(plugin_path), 1)
            
        # Apply correct signature to all SW SMI handlers.
        for func in BipFunction.get_by_prefix("SwSmiHandler"):
            self.logger.debug(f'Applying signature of EFI_SMM_HANDLER_ENTRY_POINT to 0x{func.ea:x}')
            EFI_SMM_HANDLER_ENTRY_POINT.set_at(func.ea)

        ida_loader.flush_buffers()

        # Check if efiXplorer detected any potential vulnerabilities, and if so propagate them.
        efiXplorer_json = Path(idaapi.get_input_file_path()).with_suffix('.json')
        with open(efiXplorer_json, 'r') as f:
            json_report = json.load(f)

        vulns = json_report.get('vulns')
        if not vulns:
            return

        for vuln_name in vulns:
            # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
            addresses = [hex(ea) for ea in json_report['vulns'][vuln_name]]
            self.logger.warn(f'efiXplorer: {vuln_name} occuring at {addresses}')

with closing(EfiXplorerModule()) as module:
    module.run()
