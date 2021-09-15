from functools import cached_property
from typing import Iterable
from guids.guids_db import GuidsDatabase
from .efiXplorer import Py_EfiXplorer

from ..base_module import BaseModule
from ...utils import brick_utils
from ...utils.function_locator import FunctionRecognizer

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
        self.known_callout_false_positives = []

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

    def recognize_FreePool(self):

        def _FreePool_heuristic(f: BipFunction):
            if not (f.type.nb_args == 1 and \
                    isinstance(f.type.get_arg_type(0), (BTypePtr, BTypeInt))):
                return False

            (calls_SmmFreePool, calls_FreePool) = (False, False)

            def _callback(cnode):
                nonlocal calls_SmmFreePool, calls_FreePool
                if '->SmmFreePool' in cnode.cstr:
                    print('calls SmmFreePool')
                    calls_SmmFreePool = True
                if '->FreePool' in cnode.cstr:
                    print('calls FreePool')
                    calls_FreePool = True

            f.hxcfunc.visit_cnode_filterlist(_callback, [CNodeExprCall])
            print(f'{f}: {calls_SmmFreePool} {calls_FreePool}')
            return calls_SmmFreePool and calls_FreePool

        FreePool_recognizer = FunctionRecognizer('FreePool', is_library=True)
        if FreePool_func := FreePool_recognizer.recognize_by_heuristic(_FreePool_heuristic):
            self.known_callout_false_positives.append(FreePool_func.ea)


    def handle_smm_callouts(self, callouts):
        if brick_utils.search_guid(self.EFI_SMM_RUNTIME_SERVICES_TABLE_GUID):
            self.logger.info('''Module references EFI_SMM_RUNTIME_SERVICES_TABLE_GUID,
the following call-outs are likely to be false positives''')

        for callout in callouts:
            for handler in self.smi_handlers:
                paths = brick_utils.get_paths(handler, callout)
                for path in paths:
                    if set(path) & set(self.known_callout_false_positives):
                        # We hit a known false-positive, skip that.
                        continue
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
            self.recognize_FreePool()
            self.handle_vulnerabilities(vulns)
        else:
            self.logger.success("efiXplorer didn't detect any vulnerabilities")
