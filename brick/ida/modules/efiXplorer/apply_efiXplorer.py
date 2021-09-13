from functools import cached_property
from typing import Iterable
from guids.guids_db import GuidsDatabase
from .efiXplorer import Py_EfiXplorer

from ..base_module import BaseModule
from ...utils import brick_utils

from bip.base import *
from bip.hexrays import *

class EfiXplorerModule(BaseModule):
    '''
    Analyzes the input binary using the efiXplorer plugin for IDA Pro.
    Then, formats and propagates the results while trying to avoid some common false-positives.
    '''

    EFI_SMM_RUNTIME_SERVICES_TABLE_GUID = GuidsDatabase().name2guid['SmmRsTableGuid']

    @cached_property
    def smi_handlers(self):
        return BipFunction.get_by_prefix(Py_EfiXplorer.SW_SMI_PREFIX) + \
               BipFunction.get_by_prefix(Py_EfiXplorer.CB_SMI_PREFIX)

    @staticmethod
    def format_path(addresses: Iterable):
        path = ''
        for address in addresses[:-1]:
            path += BipFunction(address).name
            path += '->'
        path += hex(addresses[-1])
        return path

    def handle_smm_callouts(self, callouts):
        if brick_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
            self.logger.info('''Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID,
the following call-outs are likely to be false positives''')

        for callout in callouts:
            for handler in self.smi_handlers():
                paths = brick_utils.get_paths(handler, callout)
                for path in paths:
                    self.logger.verbose(self.format_path(path))
        
    def handle_vulnerabilities(self, vulns):
        for vuln_type in vulns:
            addresses = [ea for ea in vulns[vuln_type]]
            if vuln_type == 'smm_callout':
                self.handle_smm_callouts(addresses)
            else:
                # In JSON all integers must be written in decimal radix. Convert them to hex for enhanched readability.
                hex_addresses = [hex(ea) for ea in addresses]
                self.logger.error(f'{vuln_type} occuring at {hex_addresses}')

    def run(self):
        efiXplorer = Py_EfiXplorer()
        efiXplorer.run(Py_EfiXplorer.Args.DISABLE_UI)

        vulns = efiXplorer.get_results().get('vulns')
        if vulns:
            self.handle_vulnerabilities(vulns)
        else:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")
