from functools import cached_property
from typing import Iterable
from guids.guids_db import GuidsDatabase
from ..efiXplorer.efiXplorer import EfiXplorerModule, EfiXplorerPlugin
from pathlib import Path

from ..base_module import BaseModule
from ...utils import brick_utils, bip_utils
from ...utils.functions_db.FreePool import FreePool

from bip.base import *
from bip.hexrays import *

class SmmCalloutsModule(BaseModule):
    '''
    Analyzes the input binary using the efiXplorer plugin for IDA Pro.
    Then, formats and propagates the results while trying to avoid some common false-positives.
    '''

    EFI_SMM_RUNTIME_SERVICES_TABLE_GUID = GuidsDatabase().name2guid['SmmRsTableGuid']

    DEPENDS_ON = [EfiXplorerModule]

    def __init__(self) -> None:
        super().__init__()
        self.known_false_positives = set()
        self.res_dir = Path(__file__).parent / 'res'
        self.include_dir = Path(__file__).parent / 'include'

    @cached_property
    def smi_handlers(self):
        return BipFunction.get_by_prefix(EfiXplorerPlugin.SW_SMI_PREFIX) + \
               BipFunction.get_by_prefix(EfiXplorerPlugin.CB_SMI_PREFIX)

    @staticmethod
    def format_path(addresses: Iterable):
        path = ''
        for address in addresses[:-1]:
            path += BipFunction(address).name
            path += '->'
        path += hex(addresses[-1])
        return path

    def match_known_false_positives(self):
        '''
        Initializes a database of functions that are known for generating false positives in efiXplorer.
        '''
        if (FreePool_ea := FreePool().match(decompiler_required=True)):
            self.known_false_positives.add(FreePool_ea)

    def _find_next_call(self, ea, limit=10):
        ins = BipInstr(ea)
        i = 0
        while i < limit and not ins.is_call:
            ea += ins.size
            ins = BipInstr(ea)
        if not ins.is_call:
            return None
        return ins

    def handle_smm_callouts(self, callouts):
        
        # Filter out the false positives.
        self.match_known_false_positives()

        smm_rt_present = bip_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID)

        for callout in callouts:

            if BipFunction(callout) in self.known_false_positives:
                # This is a function that is known to generate false positives,
                # e.g. FreePool() from EDK2.
                continue

            call_ins = self._find_next_call(callout)
            
            if smm_rt_present:    
                if call_ins is not None and 'EFI_RUNTIME_SERVICES' in call_ins.op(0).str:
                    # The module references EFI_SMM_RUNTIME_SERVICES_TABLE, so chances are all
                    # calls to UEFI runtime services are actually *NOT* callouts
                    continue

            # If we got here, we have some true callouts.
            for handler in self.smi_handlers:
                for path in brick_utils.get_paths(handler, callout):
                    self.logger.error(self.format_path(path))
                    if call_ins is not None:
                        self.logger.info(call_ins.str)
                    self.res = False

        if self.res:
            self.logger.success('No SMM callouts were identified')

    def run(self):
        efiXplorer = EfiXplorerPlugin(self.input_file, self.is_64bit)
        results = efiXplorer.get_results()

        callouts = results.get('vulns', {}).get('smm_callout', [])
        self.handle_smm_callouts(callouts)
