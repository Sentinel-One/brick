import itertools
from ..base_module import BaseModule
import re
from bip.base import *
from bip.hexrays import *
from alleycat import AlleyCatCodePaths

from ...utils.smi import CommBufferSmiHandler
from ..efiXplorer.efiXplorer import EfiXplorerModule

class ToctouModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()
        self.field_re = re.compile('CommBuffer->(field_.+)')

    DEPENDS_ON = [EfiXplorerModule]

    def _is_memref(self, node: CNodeExprMemptr):
        '''
        The decompiler may propagate expressions to make the output more readable and reduce the
        number of artificial variables, which might lead to somewhat misleading output.
        For example, for the following snippet:
            mov     rcx, [r8]       ; r8 = CommBuffer
            mov     cs:qword_37B0, rcx
        The decompiler might generate the following pseudocode:
            v5 = *CommBuffer;
            qword_37B0 = *CommBuffer;

        While the pseudocode is logically correct, it creates the illusion the CommBuffer
        in memory was accessed twice, where in reality it was only accessed once.
        To workaround this issue, we will disassemble the instruction corresponding to the dereference
        opearion and check if makes any references to memory.
        '''

        try:
            ins = BipInstr(node.closest_ea)
            if ins.mnem in ('mov', 'movzx'):
                src = ins.ops[1]
            elif ins.mnem in ('cmp', 'test'):
                src = ins.ops[0]
            else:
                self.logger.debug(f'0x{node.closest_ea:x}: unexcepted opcode {ins.str}')
                return False

            return src.is_memref
        except:
            self.logger.debug(f'Exception at {node.cstr} {node.ea}')
            return False

    def _validate_handler(self, handler: HxCFunc):

        # Reconstruct the strucutre for the CommBuffer.
        # After reconstruction, we expect to have a pointer-to-structure.
        comm_buffer_type = handler.reconstruct_comm_buffer()
        if not isinstance(comm_buffer_type, BTypePtr) or not isinstance(comm_buffer_type.children[0], BTypeStruct):
            return

        # A dictionary that maps a field name to a list of addresses that reference it.
        comm_buffer_struct = comm_buffer_type.children[0]
        fields_map = {field_name:[] for field_name, _ in comm_buffer_struct.members_info.items()}

        def callback(node: CNodeExprMemptr):
            # Check that this is an access to a field of the CommBuffer
            # e.g. CommBuffer->field_18
            match = re.match(self.field_re, node.cstr)
            if not match:
                return

            if node.has_parent:
                # Check it is not used as the left-hand side of an assignment.
                if isinstance(node.parent, CNodeExprAssignment) and node.parent.dst == node:
                    return
                if isinstance(node.parent, CNodeExprRef):
                    # The expression merely takes the address of a field (e.g. &CommBuffer->field_0)
                    return

            # Check the disassembly to see it's indeed a fetch from memory.
            if not self._is_memref(node):
                # self.logger.debug(f'Node {node.cstr} at 0x{node.ea:x} does not fetch from memory')
                return
            # else:
            #     self.logger.debug(f'Node {node.cstr} at 0x{node.ea:x} is a fetch from memory')

            # Append the address of the node to the list of references to the field.
            field_name = match.groups()[0]
            fields_map[field_name].append(node.closest_ea)

        # Process all the pointer dereferences (struct->field) carried out by the function.
        handler.hxcfunc.visit_cnode_filterlist(callback, [CNodeExprMemptr])

        for field_name, references in fields_map.items():
            if len(references) <= 1:
                # Field is fetched at most once.
                continue

            # Search for a pair of references to the same field that are reachable from one another.
            for (a, b) in itertools.combinations(references, r=2):
                if AlleyCatCodePaths(a, b).paths or AlleyCatCodePaths(b, a).paths:
                    # Differentiate between pointer and non-pointers members.
                    # TOCTOU attacks on pointers should be considered more severe.
                    if isinstance(comm_buffer_struct.members_info[field_name], BTypePtr):
                        self.logger.error(f'SMI {handler.name}: Pointer member {field_name} is fetched multiple times and might be subject to a TOCTOU attack')
                    else:
                        self.logger.warning(f'SMI {handler.name}: Member {field_name} is fetched multiple times and might be subject to a TOCTOU attack')
                    
                    self.res = False
                    break

    def run(self):
        for handler in CommBufferSmiHandler.iter_all():
            self._validate_handler(handler)

        if self.res:
            self.logger.success('No double fetches from the Comm Buffer were encountered')
