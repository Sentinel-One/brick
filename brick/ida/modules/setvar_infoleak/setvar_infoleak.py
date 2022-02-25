from ..base_module import BaseModule
from ..efiXplorer.efiXplorer import EfiXplorerModule
from ..postprocessor.postprocessor import PostprocessorModule
from ..postprocessor.uefi.rt.GetVariable import GetVariableCall
from ..postprocessor.uefi.rt.SetVariable import SetVariableCall

from bip.base import *
from bip.hexrays import *

from ...utils import bip_utils
import itertools
from alleycat import AlleyCatCodePaths

class SetVarInfoLeakModule(BaseModule):
    
    DEPENDS_ON = [PostprocessorModule, EfiXplorerModule]

    EFI_VARIABLE_RUNTIME_ACCESS = 0x0000000000000004

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def _friendly_name(node):
        '''Tries to return the variable name as a string'''

        node = node.ignore_cast
        if isinstance(node, CNodeExprRef):
            # if we have a ref (&something) we want the object under
            node = node.ops[0].ignore_cast

        if isinstance(node, CNodeExprObj):
            # if this is a global object, get name of variable from memory.
            return BipData.get_c16string(node.value)

        if isinstance(node, CNodeExprVar):
            # Local variable.
            return node.lvar_name

        # Fallback, just use the C-string.
        return node.cstr

    def validate_function(self, f: HxCFunc):

        def _is_get_variable(node: CNodeExprCall):
            if any(f'->{x}' in node.cstr for x in ('GetVariable', 'SmmGetVariable')):
                return True

        # Collect all the calls to GetVariable()
        get_variable_calls = bip_utils.collect_cnode_filterlist(f, _is_get_variable, [CNodeExprCall])
        # Wrap them
        get_variable_calls = [GetVariableCall.from_cnode(call) for call in get_variable_calls]

        def _is_set_variable(node: CNodeExprCall):
            if any(f'->{x}' in node.cstr for x in ('SetVariable', 'SmmSetVariable')):
                return True

        # Collect all the calls to SetVariable()
        set_variable_calls = bip_utils.collect_cnode_filterlist(f, _is_set_variable, [CNodeExprCall])
        # Wrap
        set_variable_calls = [SetVariableCall.from_cnode(call) for call in set_variable_calls]

        # Generate cartesian product.
        product = itertools.product(get_variable_calls, set_variable_calls)
        
        for (get_call, set_call) in product:
            
            # Check that there is path that connects both calls.
            reachable = AlleyCatCodePaths(get_call.ea, set_call.ea).paths
            if not reachable:
                continue

            # Check that both calls operate on the same variable.
            variable_name = self._friendly_name(get_call.VariableName)
            if self._friendly_name(set_call.VariableName) != variable_name:
                continue

            # DataSize must be a numeric constant.
            data_size = set_call.DataSize
            if not isinstance(data_size, CNodeExprNum):
                continue

            # DataSize = 0 is used to denote deleting a variable, benign case.
            if data_size.value == 0:
                continue

            # If possible, check that the variable has a runtime attribute.
            attrs = set_call.Attributes
            if isinstance(attrs, CNodeExprNum):
                if attrs.value & self.EFI_VARIABLE_RUNTIME_ACCESS == 0:
                    continue
                 
            # @TODO: Check that the same buffer is used in both calls?

            # If we got here, a variable that was already retrieved by the function is now
            # being set using a hardcoded size, which might disclose sensitive data.
            self.res = False
            self.logger.error(f'Function {f.bfunc.name} discloses up to {data_size.value} SMRAM bytes while calling SetVariable() on {variable_name}')

    def run(self):
        for function in HxCFunc.iter_all():
            self.validate_function(function)

        if self.res:
            self.logger.success('No functions that might disclose SMRAM contents were identified')
