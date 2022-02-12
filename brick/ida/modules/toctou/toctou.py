from ..base_module import BaseModule
import re
from bip.base import *
from bip.hexrays import *


from ..smi_nested_pointers.smi import CommBufferSmiHandler
from ..efiXplorer.efiXplorer import EfiXplorerModule

class ToctouModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()
        self.field_re = re.compile('CommBuffer->(field_.+)')

    DEPENDS_ON = [EfiXplorerModule]

    def run(self):
        
        for handler in CommBufferSmiHandler.iter_all():
            
            comm_buffer_type = handler.reconstruct_comm_buffer()
            if not isinstance(comm_buffer_type, BTypePtr) or not isinstance(comm_buffer_type.children[0], BTypeStruct):
                # Should be pointer to a structure.
                continue

            comm_buffer_struct_type = comm_buffer_type.children[0]
            nested_pointers = {mem_name:0 for mem_name, mem_type in comm_buffer_struct_type.members_info.items() if isinstance(mem_type, BTypePtr)}

            def callback(node: CNode):
                match = re.match(self.field_re, node.cstr)
                if not match:
                    return

                field_name = match.groups()[0]
                if not field_name in nested_pointers:
                    return

                if node.has_parent and isinstance(node.parent, CNodeExprAssignment) and node.parent.dst == node:
                    return

                nested_pointers[field_name] += 1

            handler.hxcfunc.visit_cnode_filterlist(callback, [CNodeExprMemptr])

            for member_name, occurences in nested_pointers.items():
                if occurences > 1:
                    self.res = False
                    self.logger.error(f'SMI {handler.name}: Comm buffer member {member_name} is fetched {occurences} times and might be subject to a TOCTOU attack')

            if self.res:
                self.logger.success('No double fetches from the Comm Buffer were encountered')
                