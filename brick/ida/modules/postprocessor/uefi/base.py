from abc import abstractmethod, abstractproperty
from bip.base import *
from bip.hexrays import *

def set_cnode_name(cnode, name: str):
    # Convert to CamelCase.
    # name = name.title().replace('_', '')

    if isinstance(cnode, CNodeExprRef):
        # If we have a ref (&something) we want the object under.
        cnode = cnode.ops[0].ignore_cast

    if isinstance(cnode, CNodeExprVar):
        cnode.lvar.name = 'v_' + name
    elif isinstance(cnode, CNodeExprObj):
        GetElt(cnode.value).name = f'g_{name}_{hex(cnode.ea)}'

def set_cnode_type(cnode, t: BipType):
    if isinstance(cnode, CNodeExprRef):
        # If we have a ref (&something) we want the object under.
        cnode = cnode.ops[0].ignore_cast
    if isinstance(cnode, CNodeExprVar):
        cnode.lvar.type = t
    elif isinstance(cnode, CNodeExprObj):
        t.set_at(cnode.value)

class CNodeExprIndirectCall(CNodeExprCall):
    '''Same as CNodeExprCall, but allows to set the type of an indirect function call.
    '''

    @classmethod
    def from_cnode(cls, cnode):
        return cls(cnode._cexpr, cnode.hxcfunc, cnode.parent)

    @abstractproperty
    def PROTOTYPE(self):
        pass

    @abstractmethod
    def set_call_type(self):
        instr = BipInstr(self.ea)

        # standard call:
        # call    qword ptr [reg+off]
        # or tail call:
        # jmp     qword ptr [reg+off]
        if instr.mnem not in ('call', 'jmp'):
            raise ValueError(f'Unexpected instruction {instr.mnem} at 0x{instr.ea:x}')

        instr.op(0).type_info = self.PROTOTYPE

    def process(self):
        pass

