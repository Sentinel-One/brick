from ..base_module import BaseModule
from ..efiXplorer.efiXplorer import EfiXplorerModule
from ..postprocessor.postprocessor import PostprocessorModule
from ..postprocessor.uefi.rt.GetVariable import GetVariableCall
from ..postprocessor.uefi.rt.SetVariable import SetVariableCall

from bip.base import *
from bip.hexrays import *

class SetVarInfoLeakModule(BaseModule):
    
    DEPENDS_ON = [PostprocessorModule, EfiXplorerModule]

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

        # Variables that were encountered so far.
        variables = set()

        def _handle_get_set_variable(node: CNodeExprCall):
            if any(f'->{x}' in node.cstr for x in ('GetVariable', 'SmmGetVariable')):
                # Handle GetVariable
                get_variable_call = GetVariableCall.from_cnode(node)
                print(get_variable_call)
                
                variable_name = self._friendly_name(get_variable_call.VariableName)
                variables.add(variable_name)
                
            elif any(f'->{x}' in node.cstr for x in ('SetVariable', 'SmmSetVariable')):
                # Handle SetVariable
                set_variable_call = SetVariableCall.from_cnode(node)
                print(set_variable_call)
                
                variable_name = self._friendly_name(set_variable_call.VariableName)
                if variable_name not in variables:
                    # Variable was set without being retrieved first, benign case.
                    return
                
                data_size = set_variable_call.DataSize
                if not isinstance(data_size, CNodeExprNum):
                    # DataSize is not a constant, benign case.
                    return

                if data_size.value == 0:
                    # DataSize = 0 is used to denote deleting a variable, benign case.
                    return

                # If we got here, a variable that was already retrieved by the function is now
                # being set using a hardcoded size, which might disclose sensitive data.
                self.res = False
                self.logger.error(f'Function {f.bfunc.name} discloses up to {data_size.value} SMRAM bytes while calling SetVariable() on {variable_name}')
                
            else:
                # Nothing interesting
                pass

        f.visit_cnode_filterlist(_handle_get_set_variable, [CNodeExprCall])

    def run(self):
        for function in HxCFunc.iter_all():
            self.validate_function(function)

        if self.res:
            self.logger.success('No functions that might disclose SMRAM contents were identified')
