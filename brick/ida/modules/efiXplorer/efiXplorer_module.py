from functools import cached_property
from typing import Iterable
from guids.guids_db import GuidsDatabase
from .efiXplorer_plugin import EfiXplorerPlugin
from pathlib import Path

from ..base_module import BaseModule
from ...utils import brick_utils, bip_utils
from ...utils.function_matcher import FunctionMatcher

from bip.base import *
from bip.hexrays import *

class EfiXplorerModule(BaseModule):
    '''
    Analyzes the input binary using the efiXplorer plugin for IDA Pro.
    Then, formats and propagates the results while trying to avoid some common false-positives.
    '''

    EFI_SMM_RUNTIME_SERVICES_TABLE_GUID = GuidsDatabase().name2guid['SmmRsTableGuid']

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

        def FreePool_heuristic(f: BipFunction):
            # The prototype of the function must match EFI_STATUS (void *).
            if not (f.type.nb_args == 1 and \
                    isinstance(f.type.get_arg_type(0), BTypePtr) and \
                    isinstance(f.type.return_type, (BTypeInt))):
                return False

            # Collect all the calls used to free pool memory.
            def is_smm_free_pool(node: CNodeExprCall):
                return '->SmmFreePool' in node.cstr
            def is_bs_free_pool(node: CNodeExprCall):
                return '->FreePool' in node.cstr

            smm_free_pool = bip_utils.collect_cnode_filterlist(f.hxcfunc, is_smm_free_pool, [CNodeExprCall])
            bs_free_pool = bip_utils.collect_cnode_filterlist(f.hxcfunc, is_bs_free_pool, [CNodeExprCall])

            # Each of these functions should be called EXACLY once.
            if len(smm_free_pool) != 1 or len(bs_free_pool) != 1:
                return False

            # The same pointer should be forwarded to both functions.
            if smm_free_pool[0].args[0].ignore_cast.lvar != f.hxcfunc.args[0] or \
               bs_free_pool[0].args[0].ignore_cast.lvar != f.hxcfunc.args[0]:
                return False
            
            # All tests passed.
            return True

        # See https://github.com/tianocore/edk2/blob/master/MdePkg/Library/SmmMemoryAllocationLib/MemoryAllocationLib.c
        FreePool_matcher = FunctionMatcher('FreePool', is_library=True)

        if FreePool_func := FreePool_matcher.match_by_heuristic(FreePool_heuristic, decompiler_required=True):
            self.known_false_positives.add(FreePool_func.ea)

        elif FreePool_func := FreePool_matcher.match_by_diaphora(self.res_dir / 'SmmMemoryAllocationLib.sqlite', 0.8):
            self.known_false_positives.add(FreePool_func.ea)

    def handle_smm_callouts(self, callouts):
        self.match_known_false_positives()

        if bip_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
            self.logger.info('''Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID,
the following call-outs are likely to be false positives''')

        for callout in callouts:
            if BipFunction(callout).ea in self.known_false_positives:
                # We hit a known false-positive, skip that.
                continue

            for handler in self.smi_handlers:
                for path in brick_utils.get_paths(handler, callout):
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

    def load_headers(self):
        for header in self.include_dir.iterdir():
            BipType.import_c_header(str(header))

    def run(self):
        self.load_headers()
        
        efiXplorer = EfiXplorerPlugin(self.input_file, self.is_64bit)
        efiXplorer.run(EfiXplorerPlugin.Args.DISABLE_UI)

        vulns = efiXplorer.get_results().get('vulns')
        if vulns:
            self.handle_vulnerabilities(vulns)
        else:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")
