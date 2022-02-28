from ..base_module import BaseModule

from bip.base import *
from bip.hexrays import *

from ..efiXplorer.efiXplorer import EfiXplorerModule
from ...utils.smi import CommBufferSmiHandler

class LowSmramCorruptionModule(BaseModule):
    '''
    Scans for SMI handlers that don't properly validate the size of the communication buffer.
    Malicious actors can place the communication buffer just below the SMRAM range,
    such that any attempt to write to the communication buffer will result in overwriting SMRAM.
    '''

    def __init__(self) -> None:
        super().__init__()

    DEPENDS_ON = [EfiXplorerModule]

    @staticmethod
    def derefs_CommBufferSize(handler: CommBufferSmiHandler):
        if not handler.CommBufferSize._lvar.used:
            # CommBufferSize is not touched at all.
            return False

        def _derefs_CommBufferSize(node: CNodeExprPtr):
            '''Does the node correspond to a dereference operation on CommBufferSize? (i.e. *CommBufferSize)'''
            dereferenced = node.ops[0].ignore_cast

            if isinstance(dereferenced, CNodeExprVar) and (dereferenced.lvar == handler.CommBufferSize):
                # Found our target node, so interrupt the search.
                return False

        # If the search was interrupted, it means we found a node that dereferences CommBufferSize.
        interrupted = not handler.hxcfunc.visit_cnode_filterlist(_derefs_CommBufferSize, [CNodeExprPtr])
        return interrupted

    @staticmethod
    def validates_CommBuffer_not_in_smram(handler: CommBufferSmiHandler):

        def _validates_CommBuffer_not_in_smram(node: CNodeExprCall):

            # Check that the call is to SmmIsBufferOutsideSmmValid() from EDK2 or ValidateMemoryBuffer() from AMI.
            if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                # Now check if the CommBuffer is being validated.
                buffer = node.args[0].ignore_cast
                if isinstance(buffer, CNodeExprVar) and (buffer.lvar == handler.CommBuffer):
                    # Found our target node, so interrupt the search.
                    return False

        # If the search was interrupted, it means we found a node that validates CommBuffer does not overlap SMRAM.
        interrupted = not handler.hxcfunc.visit_cnode_filterlist(_validates_CommBuffer_not_in_smram, [CNodeExprCall])
        return interrupted

    def run(self):
        for handler in CommBufferSmiHandler.iter_all():

            if not handler.CommBuffer._lvar.used:
                # If the CommBuffer is not referenced at all, the handler is assumed to be safe.
                self.logger.success(f'SMI {handler} considered safe: does not reference the CommBuffer at all')
                continue

            if self.derefs_CommBufferSize(handler):
                # The handler checks that the CommBuffer does not overlap SMRAM simply by dereferencing the
                # CommBufferSize argument and probably comparing it against a hardcoded value.
                # This is safe because SmmEntryPoint calls SmmIsBufferOutsideSmmValid(CommBuffer, *CommBufferSize)
                # prior to passing control to the handler.
                self.logger.success(f'SMI {handler} considered safe: derefernces *CommBufferSize')
                continue

            if self.validates_CommBuffer_not_in_smram(handler):
                # Even if that handler does not reference CommBufferSize, it can still make the
                # CommBuffer does not overlap with SMRAM simply by passing it to a validation
                # routine such as SmmIsBufferOutsideSmmValid, alongside the size of the expected input
                # e.g. SmmIsBufferOutsideSmmValid(CommBuffer, 100)
                self.logger.success(f'SMI {handler} considered safe: passes the CommBuffer to a validation routine')
                continue

            # If we got here, the handler can potentially be abused by attackers to corrupt the
            # lower portion of SMRAM.
            self.logger.error(f'SMI {handler} considered vulnerable: might be abused to corrupt the lower portion of SMRAM')

        if self.res:
            self.logger.success('No SMI that omits checking CommBufferSize was found')