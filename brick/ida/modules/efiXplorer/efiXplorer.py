import ida_loader
import idaapi
from pathlib import Path
from enum import IntEnum
import json
from functools import cached_property

class EfiXplorerError(RuntimeError):
    pass

class Py_EfiXplorer:
    '''
    Provides a Pythonic interface to the EfiXplorer plugin.
    '''

    # Prefix for legacy software SMIs.
    SW_SMI_PREFIX = 'SwSmiHandler_'
    # Prefix for CommBuffer based SMIs.
    CB_SMI_PREFIX = 'SmiHandler_'

    class Args(IntEnum):
        '''
        Represents the supported arguments that can be passed to EfiXplorer.
        See https://github.com/binarly-io/efiXplorer/blob/master/efiXplorer/efiXplorer.cpp for more details.
        '''
        DISABLE_UI        = 0b01
        DISABLE_VULN_HUNT = 0b10

    def __init__(self) -> None:
        self.file = idaapi.get_input_file_path()

    @property
    def plugin_path(self):
        parent_dir = Path(__file__).parent

        inf_struct = idaapi.get_inf_structure()
        if inf_struct.is_64bit():
            _plugin_path = parent_dir / 'efiXplorer64.dll'
        else:
            # 32 bits
            _plugin_path = parent_dir / 'efiXplorer.dll'

        return _plugin_path

    def run(self, args=0):
        rc = ida_loader.load_and_run_plugin(str(self.plugin_path), args)
        if not rc:
            raise EfiXplorerError(f'efiXplorer analysis of {self.file} failed')

    def get_results(self) -> dict:
        json_report_path = Path(self.file).with_suffix('.json')
        with open(json_report_path, 'r') as f:
            return json.load(f)
