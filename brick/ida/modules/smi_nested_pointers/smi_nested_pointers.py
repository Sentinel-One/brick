from ...utils.functions_db.SmmIsBufferOutsideSmmValid import SmmIsBufferOutsideSmmValid
from ..base_module import BaseModule
from ..efiXplorer.efiXplorer import EfiXplorerModule
from ..postprocessor.postprocessor import PostprocessorModule
from ...utils import bip_utils
from ...utils.smi import CommBufferSmiHandler

from bip.base import *
from bip.hexrays import *


class SmiNestedPointersModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    DEPENDS_ON = [PostprocessorModule, EfiXplorerModule]

    def _is_shallow_pointer_validation(self, handler: CommBufferSmiHandler, field_name: str):
        '''
        If we are lucky enough, the handler calls the validation function directly on the nested pointer.
        '''
        def __validation_callback(node: CNodeExprCall):
            if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                buffer = node.args[0].ignore_cast
                
                if isinstance(buffer, CNodeExprMemptr) and buffer.cstr == f'CommBuffer->{field_name}':
                    # Interrupt the search.
                    return True

        return bip_utils.search_cnode_filterlist(handler.hxcfunc, __validation_callback, [CNodeExprCall])

    def _is_deep_pointer_validation(self, handler: CommBufferSmiHandler):
        '''
        Our data-flow analysis is pretty limited at the moment.
        '''
        def __validation_callback(node: CNodeExprCall):
            if 'SmmIsBufferOutsideSmmValid' in node.cstr or '->ValidateMemoryBuffer' in node.cstr:
                buffer = node.args[0].ignore_cast
                if isinstance(buffer, CNodeExprVar) and buffer.lvar != handler.CommBuffer:
                    # Found a validation of a local variable which is not the CommBuffer itself.
                    return True

        return bip_utils.search_cnode_filterlist(handler.hxcfunc, __validation_callback, [CNodeExprCall], recursive=True)

    def _is_handler_vulnerable(self, handler: CommBufferSmiHandler):
        if not handler.CommBuffer._lvar.used:
            # The CommBuffer is not used, so the handler is implicitly safe.
            self.logger.success(f'SMI {handler.name} considered safe: does not reference CommBuffer')
            return False

        # Reconstruct the structure of CommBuffer.
        comm_buffer_type = handler.reconstruct_comm_buffer()
        if not isinstance(comm_buffer_type, BTypePtr) or not isinstance(comm_buffer_type.children[0], BTypeStruct):
            return

        # Check if the Comm Buffer holds any nested pointers
        members_info = comm_buffer_type.children[0].members_info.items()
        nested_pointers = [field_name for field_name, field_type in members_info if isinstance(field_type, BTypePtr)]
        if not nested_pointers:
            self.logger.success(f'SMI {handler.name} considerd safe: CommBuffer does not contain nested pointers')
            return False

        for ptr in nested_pointers[:]: # Operate on a copy
            if self._is_shallow_pointer_validation(handler, ptr):
                self.logger.success(f'SMI {handler}: nested pointer {ptr} is being sanitized')
                nested_pointers.remove(ptr)

        if not nested_pointers:
            # No nested pointers were left unverified.
            return False

        if not self._is_deep_pointer_validation(handler):
            # No additional validation calls were found, which necessarily means some nested pointers are not validated.
            self.logger.error(f'SMI {handler}: missing validation of nested pointers {nested_pointers}')
        else:
            # Additional validation calls were found, but we can't be sure it's validating the nested pointers.
            # Issue a warning for that.
            self.logger.warning((f'SMI {handler}: cannot deduce validation status of {nested_pointers}'))

    def run(self):
        if sibosv := SmmIsBufferOutsideSmmValid().match():
            self.logger.debug(f'Found SmmIsBufferOutsideSmmValid at 0x{sibosv.ea:x}')

        for handler in CommBufferSmiHandler.iter_all():
            if self._is_handler_vulnerable(handler):
                self.logger.error(f'SMI Handler {handler} does not validate pointers in the Communication Buffer')
        