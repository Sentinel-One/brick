from functools import cached_property
from ...utils.type_reconstructor import TypeReconstructor, HexRaysCodeXplorerError
from bip.base import *
from bip.hexrays import *

from ...utils import brick_utils, bip_utils
import re

class SmiHandler(BipFunction):
    
    def __init__(self, ea):
        super().__init__(ea=ea)
        self.memory_access_re = re.compile('MEMORY\[\w+\]')

    @classmethod
    def iter_all(cls):
        for subcls in cls.__subclasses__():
            for smi in subcls.iter_all():
                yield smi

    @property
    def hex_ea(self):
        return hex(self.ea)[2:].lower()

    @property
    def DispatchHandle(self):
        return self.hxcfunc.args[0]

    @property
    def Context(self):
        return self.hxcfunc.args[1]

    @property
    def CommBuffer(self):
        return self.hxcfunc.args[2]

    @property
    def CommBufferSize(self):
        return self.hxcfunc.args[3]

    def check_prototype(self):
        # Do some sanity checks on the arguments.
        if not (self.type.nb_args == 4 and \
                self.type.get_arg_name(0) == 'DispatchHandle' and \
                self.type.get_arg_name(1) == 'Context' and \
                self.type.get_arg_name(2) == 'CommBuffer' and \
                self.type.get_arg_name(3) == 'CommBufferSize'):
            return False

        return True

    @cached_property
    def attack_surface(self):

        def is_attack_surface(node: CNode):
            '''
            Does the node represents a potential attack surface for the current SMI.
            '''

            candidate = None

            if isinstance(node, CNodeExprCall):
                if any(x in node.cstr for x in ('GetVariable', 'SmmGetVariable', 'ReadSaveState')):
                    # Calls one of {GetVariable, SmmGetVariable, ReadSaveState}.
                    candidate = node

            if isinstance(node, CNodeExprMemptr):
                if 'CpuSaveState' in node.cstr:
                    # Reads the SMM save state directly via gSmst->CpuSaveState[CpuIndex].
                    candidate = node

            # if isinstance(node, CNodeExprObj):
            #     # Is this an access to an hardcoded address?
            #     if re.match(self.memory_access_re, node.cstr):
            #         # Filter out write operations.
            #         if node.has_parent and isinstance(node.parent, CNodeExprAssignment) and node == node.parent.dst:
            #             # The MEMORY node is the destination and does not contribute to the overall attack surface.
            #             pass
            #         else:
            #             candidate = node

            # Last but not least, make sure that the candidate node is reachable from the SMI.
            if candidate:
                return brick_utils.path_exists(self, candidate)

        return bip_utils.collect_cnode_filterlist(None, is_attack_surface, [CNodeExprCall, CNodeExprMemptr, CNodeExprObj])

class LegacySwSmiHandler(SmiHandler):
    '''
    Represents a legacy software SMI handler that is registered via the EfiSmmSwDispatch(2)Protocol.
    '''

    PREFIX = 'SwSmiHandler'

    @classmethod
    def iter_all(cls):
        for smi in (cls(f.ea) for f in BipFunction.get_by_prefix(cls.PREFIX)):
            if smi.check_prototype():
                yield smi


class CommBufferSmiHandler(SmiHandler):
    '''
    Represent an SMI handler that receives its arguments via the Communication Buffer.
    '''

    PREFIX = 'SmiHandler'

    def __init__(self, ea):
        super().__init__(ea)

    @classmethod
    def iter_all(cls):
        for smi in (cls(f.ea) for f in BipFunction.get_by_prefix(cls.PREFIX)):
            if smi.check_prototype():
                yield smi

    @cached_property
    def attack_surface(self):
        
        # The CommBuffer is also a part of the attack surface.
        return super().attack_surface + \
               bip_utils.collect_cnode_filterlist(self.hxcfunc, lambda node: 'CommBuffer' == node.lvar_name, [CNodeExprVar])

    def is_comm_buffer_used(self):
        # Some SMI handlers don't use the CommBuffer at all.
        return self.CommBuffer._lvar.used

    def reconstruct_comm_buffer(self):
        '''Reconstructs the layout of the Communication Buffer.
        '''

        # Set the type for the Comm Buffer to an integer.
        # That might help in collapsing some casts in the decompiled pseudocode.
        comm_buffer_arg = self.hxcfunc.args[2]
        comm_buffer_arg.type = BipType.from_c('UINTN')
        self.hxcfunc.invalidate_cache()

        # print('Set comm buffer type to UINTN')
        comm_buffer_struct_name = f'CommBuffer_{self.hex_ea}'

        try:
            comm_buffer_struct_type = BipType.from_c(f'{comm_buffer_struct_name} *')
        except RuntimeError:
            comm_buffer_struct_type = None

        if comm_buffer_struct_type is None:
            reconstructor = TypeReconstructor()
            try:
                reconstructor.reconstruct_type(self.ea, 'CommBuffer', comm_buffer_struct_name)
                # Type reconstruction was successful, so we should be able to retrieve the actual type object from its name.
                comm_buffer_struct_type = BipType.from_c(f'{comm_buffer_struct_name} *')
            except HexRaysCodeXplorerError:
                # Failed to reconstruct the structure, so fall back into an opaque void *
                comm_buffer_struct_type = BipType.from_c(f'void *')
            
        # Set the type for the Comm Buffer
        comm_buffer_arg.type = comm_buffer_struct_type
        self.hxcfunc.invalidate_cache()

        return comm_buffer_struct_type
