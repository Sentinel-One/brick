from ..base_module import BaseModule
from ...utils import brick_utils

from bip.base import *

import re
class CsegOnlyModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def run(self):
        SMRAM_CSEG_ADDRESSES = (
            '0A0000h', # Base address
            '0BFFFFh', # End address
            '1FFFFh',  # Size
        )

        NOT_HEX_DIGIT = '[^0-9A-F]'

        smram_cseg_regexs = []
        for address in SMRAM_CSEG_ADDRESSES:
            smram_cseg_regexs.append(re.compile(
                rf"""{NOT_HEX_DIGIT}{address}   # The address is preceded by a symbol which is not a hexadecimal digit, e.g. [rbp-0A0000h]
                     |
                     ^{address}                 # The address is not preceded by anything""", re.VERBOSE))

        functions_map = { f: 0 for f in BipFunction.iter_all() }

        # We rely on the renaming capabilities of efiXplorer.
        smi_handlers = BipFunction.get_by_prefix("SwSmiHandler") + BipFunction.get_by_prefix("Handler")

        for func in BipFunction.iter_all():
            for instr in func.instr_iter:
                for op in instr.ops:
                    for regex in smram_cseg_regexs:
                        if not regex.search(op.str):
                            # Instruction does not contain immediate values related to CSEG.
                            continue

                        functions_map[func] += 1

        for func, counter in functions_map.items():
            if counter < 2:
                # We want at least two occurences of magic numbers associated with CSEG per function.
                continue

            # Check that the function is reachable from a SMI handler.
            for smi in smi_handlers:
                if brick_utils.get_paths(func, smi):
                    # Report that a potentially vulnerable function was found.
                    self.logger.warning(f'Function 0x{func.ea:x} contains references to CSEG-only addresses')
                    self.res = False
        
        if self.res:
            self.logger.success('No SMIs that have CSEG specific behavior were found')
            
