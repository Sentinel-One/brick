import ida_loader
from pathlib import Path
from enum import IntEnum
import json

from ..base_module import BaseModule
from ..preprocessor.preprocessor import PreprocessorModule

class EfiXplorerError(RuntimeError):
    '''
    Raised when efiXplorer fails to analyze the input file.
    '''
    pass

class EfiXplorerPlugin:
    '''
    Provides a Pythonic interface to the EfiXplorer plugin.
    '''

    # Prefix for legacy software SMIs.
    SW_SMI_PREFIX = 'SwSmiHandler'
    # Prefix for CommBuffer based SMIs.
    CB_SMI_PREFIX = 'ChildSmiHandler'
    # Prefix for any unrecognized protocol GUID.
    PROPRIETARY_PROTOCOL_PREFIX = 'ProprietaryProtocol'

    class Args(IntEnum):
        '''
        Represents the supported arguments that can be passed to EfiXplorer.
        See https://github.com/binarly-io/efiXplorer/blob/master/efiXplorer/efiXplorer.cpp for more details.
        '''
        DISABLE_UI        = 0b01
        DISABLE_VULN_HUNT = 0b10

    def __init__(self, input_file, is_64bit) -> None:
        super().__init__()
        self.input_file = input_file

        if is_64bit:
            efiXplorer_plugin = 'efiXplorer64'
        else:
            # 32-bits
            efiXplorer_plugin = 'efiXplorer'

        self.plugin = ida_loader.load_plugin(efiXplorer_plugin)

    def run(self, args=0):
        '''
        Kicks off the analysis of the input file using efiXplorer.
        Optional argument can be passed to customize the analysis.
        '''

        rc = ida_loader.run_plugin(self.plugin, args)
        
        if not rc:
            raise EfiXplorerError(f'efiXplorer failed to analyze {self.input_file}')

    def get_results(self) -> dict:
        '''
        Returns the resulting report file formatted as a dictionary.
        '''

        json_report_path = Path(self.input_file).with_suffix('.json')

        if not json_report_path.exists():
            json_report_path = Path(self.input_file + '.json')

        if not json_report_path.exists():
            raise EfiXplorerError(f'Could not find efiXplorer results file for {self.input_file}')

        with open(json_report_path, 'r') as f:
            return json.load(f)

class EfiXplorerModule(BaseModule):
    '''
    Analyzes the input binary using the efiXplorer plugin for IDA Pro.
    Then, formats and propagates the results while trying to avoid some common false-positives.
    '''

    DEPENDS_ON = [PreprocessorModule]

    def run(self):
        efiXplorer = EfiXplorerPlugin(self.input_file, self.is_64bit)
        efiXplorer.run(EfiXplorerPlugin.Args.DISABLE_UI)
        
        # Report vulnerabilities.
        results = efiXplorer.get_results()
        for (bugtype, instances) in results.get('vulns', {}).items():
            if bugtype == 'smm_callout':
                # We have a dedicated module for callout vulnerabilities.
                continue
            instances = [f'0x{i:x}' for i in instances]
            self.logger.error(f'efiXplorer detected {bugtype} at {instances}')
