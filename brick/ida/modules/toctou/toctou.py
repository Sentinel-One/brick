from ..base_module import BaseModule
import re
from bip.base import *
from bip.hexrays import *


from ..smi_nested_pointers.smi import CommBufferSmiHandler


class ToctouModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def run(self):
        
        for handler in CommBufferSmiHandler.iter_all():
            
            comm_buffer_type = handler.reconstruct_comm_buffer()
            if not isinstance(comm_buffer_type, BTypePtr) or not isinstance(comm_buffer_type.children[0], BTypeStruct):
                # Should be pointer to a structure.
                continue

            comm_buffer_struct_type = comm_buffer_type.children[0]
            nested_pointers = {mem_name:0 for mem_name, mem_type in comm_buffer_struct_type.members_info.items() if isinstance(mem_type, BTypePtr)}

            def callback(cnode):
                match = re.match('CommBuffer->(field_.+)', cnode.cstr)
                if not match:
                    return

                field_name = match.groups()[0]
                if not field_name in nested_pointers:
                    return

                nested_pointers[field_name] += 1

            handler.hxcfunc.visit_cnode_filterlist(callback, [CNodeExprMemptr])

            for mem_name, occurences in nested_pointers.items():
                if occurences > 1:
                    self.logger.error(f'Comm buffer member {mem_name} is fetched {occurences} times and might be subject to a TOCTOU attack')
            # self.logger.info(nested_pointers)