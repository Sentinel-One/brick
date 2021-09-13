from pathlib import Path
import json
from typing import Iterable
import uuid
from guids.guids_db import GuidsDatabase

from ..base_module import BaseModule
from ...utils import brick_utils

import ida_loader
import idaapi

from bip.base import *
from bip.hexrays import *

class EfiXplorerModule(BaseModule):

    # arg = 1 (01): disable_ui
    DISABLE_UI = 1

    EFI_SMM_RUNTIME_SERVICES_TABLE_GUID = GuidsDatabase().name2guid['SmmRsTableGuid']

    LEGACY_SW_SMI_PREFIX = 'SwSmiHandler'
    COMM_BUFFER_SMI_NAME = 'Handler'

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

    def get_smi_handlers(self):
        return BipFunction.get_by_prefix('SwSmiHandler') + BipFunction.get_by_prefix("Handler")

    @staticmethod
    def format_path(addresses: Iterable):
        path = ''
        for address in addresses[:-1]:
            path += BipFunction(address).name
            path += '->'
        path += hex(addresses[-1])
        return path

    def handle_smm_callouts(self, callouts):
        for callout in callouts:
            for smi in self.get_smi_handlers():
                paths = brick_utils.get_paths(smi, callout)
                for path in paths:
                    self.logger.verbose(self.format_path(path))

        if brick_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
            self.logger.info('Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs likely to be false positive')
        else:
            self.logger.warning('Module does not reference EFI_SMM_RUNTIME_SERVICES_TABLE_GUID, call-outs might be true positives')

    def propagate_vulns(self):
        vulns = self.json_report().get('vulns', [])
        if vulns:
            self.res = False

        for vuln_name in vulns:
            addresses = [ea for ea in self.json_report()['vulns'][vuln_name]]
            # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
            hex_addresses = [hex(ea) for ea in addresses]
            self.logger.error(f'{vuln_name} occuring at {hex_addresses}')

            if vuln_name == 'smm_callout':
                self.handle_smm_callouts(addresses)
        
        if self.res:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")

    def run(self):
        ida_loader.load_and_run_plugin(str(self.plugin_path), self.DISABLE_UI)
        # Check if efiXplorer detected any potential vulnerabilities, and if so propagate them.
        self.propagate_vulns()
         
