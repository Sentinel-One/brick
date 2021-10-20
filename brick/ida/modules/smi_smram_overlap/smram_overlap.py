from ..base_module import BaseModule

from bip.base import *
from bip.hexrays import *


from ..smi_nested_pointers.smi import CommBufferSmiHandler

class SmramOverlapModule(BaseModule):
    '''
    Scans for SMI handlers that don't properly validate the size of the communication buffer.
    Malicious actors can place the communication buffer just below the SMRAM range,
    such that any attempt to write to the communication buffer will result in overwriting SMRAM.
    '''

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def derefs_CommBufferSize(handler: CommBufferSmiHandler):

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
                continue

            if not handler.CommBufferSize._lvar.used:
                # If CommBufferSize is not referenced at all, the handler is potentially vulnerable.
                self.res = False
                self.logger.error(f'SMI {handler.name} does not reference CommBufferSize, check for potential overlap with SMRAM')
                continue

            # If we got here, it means CommBufferSize is referenced. Still, to mark the handler as safe CommBufferSize must either either be:
            # 1. Dereferenced to retrieve the actual size (*CommBufferSize)
            # 2. Passed to a buffer validation routine such as SmmIsBufferOutsideSmmValid.

            if self.derefs_CommBufferSize(handler):
                # The handler checks that the CommBuffer does not overlap SMRAM simply by dereferencing the
                # CommBufferSize argument.
                continue
            
            if self.validates_CommBuffer_not_in_smram(handler):
                # The handler checks that the CommBuffer does not overlap SMRAM by passing it to a validation routine
                # such as SmmIsBufferOutsideSmmValid.
                continue

        if self.res:
            self.logger.success('No SMI that omits checking CommBufferSize was found')