from pathlib import Path
import json
import uuid

from ..base_module import BaseModule
from .. import brick_utils

import ida_loader
import idaapi

from bip.base import *
from bip.hexrays import *

class EfiXplorerModule(BaseModule):

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

    def propagate_vulns(self):
        vulns = self.json_report().get('vulns', [])
        if vulns:
            self.res = False

        for vuln_name in vulns:
            # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
            addresses = [hex(ea) for ea in self.json_report()['vulns'][vuln_name]]
            self.logger.error(f'{vuln_name} occuring at {addresses}')

            if vuln_name == 'smm_callout':
                if brick_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
                    self.logger.info('Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs likely to be false positive')
                else:
                    self.logger.warning('Module does not reference EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs might be true positives')
        
        if self.res:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")

    def run(self):
        ida_loader.load_and_run_plugin(str(self.plugin_path), self.DISABLE_UI)
        # Check if efiXplorer detected any potential vulnerabilities, and if so propagate them.
        self.propagate_vulns()
         
