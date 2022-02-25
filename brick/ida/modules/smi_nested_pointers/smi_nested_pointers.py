from ...utils.functions_db.SmmIsBufferOutsideSmmValid import SmmIsBufferOutsideSmmValid
from ..base_module import BaseModule
from ..efiXplorer.efiXplorer import EfiXplorerModule
from ..postprocessor.postprocessor import PostprocessorModule
from ...utils import bip_utils

from bip.base import *
from bip.hexrays import *


from .smi import CommBufferSmiHandler


class SmiNestedPointersModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    DEPENDS_ON = [PostprocessorModule, EfiXplorerModule]

    def _is_handler_vulnerable(self, handler: CommBufferSmiHandler):
        if not handler.CommBuffer._lvar.used:
            # The CommBuffer is not used, so the handler is implicitly safe.
            self.logger.success(f'SMI {handler.name} considered safe: does not reference CommBuffer')
            return False

        # Check if the Comm Buffer holds any nested pointers
        comm_buffer_type = handler.reconstruct_comm_buffer()
        if not any(isinstance(member, BTypePtr) for member in comm_buffer_type.children[0].children):
            self.logger.success(f'SMI {handler.name} considerd safe: CommBuffer does not contain nested pointers')
            return False

        def _is_nested_pointer_validation(node: CNodeExprCall):
            '''A callback function that inspects call statements.
            '''
            if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                buffer = node.args[0].ignore_cast
                
                if isinstance(buffer, CNodeExprVar) and buffer.lvar == handler.CommBuffer:
                    # Called on the CommBuffer itself. This has no meaning for us.
                    return False

                # Called on something other than the CommBuffer.
                # @TODO: Think how to validate this is indeed a nested pointer.
                return True

        # Recursively scan calls made by the handler.
        if bip_utils.search_cnode_filterlist(handler.hxcfunc, _is_nested_pointer_validation, [CNodeExprCall], recursive=True):
            self.logger.success(f'SMI {handler.name} seems to validate pointers nested in the CommBuffer')
            return False

        # If we got here it means the CommBuffer seems to contain nested pointes, but we didn't
        # manage to find any call to a function that validates these pointers do not point to SMRAM.
        return True

    def run(self):
        if sibosv := SmmIsBufferOutsideSmmValid().match():
            self.logger.debug(f'Found SmmIsBufferOutsideSmmValid at 0x{sibosv.ea:x}')

        for handler in CommBufferSmiHandler.iter_all():
            if self._is_handler_vulnerable(handler):
                self.logger.error(f'SMI Handler {handler} does not validate pointers in the Communication Buffer')
        