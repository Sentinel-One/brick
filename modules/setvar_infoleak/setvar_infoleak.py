from base_module import BaseModule

import brick_utils

from bip.base import *
from bip.hexrays import *
import ida_hexrays

class SetVarInfoLeakModule(BaseModule):

    SET_VARIABLE_PROTOTYPE = """EFI_STATUS
        (__fastcall *) (
            CHAR16 *VariableName,
            EFI_GUID *VendorGuid,
            UINT32 Attributes,
            UINTN DataSize,
            void * Data
        )"""
    
    def __init__(self) -> None:
        super().__init__()
        self.GetVariable_calls = []
        self.SetVariable_calls = []
        # A dictionary that maps a variable name to a list of functions that called GetVariable() on it.
        self.var_name_to_GetVariable = {}

    def fix_SetVariable_prototype(self):
        
        def _call_node_callback(cnode):
            if '->SetVariable' in cnode.cstr or '->SmmSetVariable' in cnode.cstr:
                brick_utils.set_indirect_call_type(cnode.ea, self.SET_VARIABLE_PROTOTYPE)

        for func in BipFunction.iter_all():
            try:
                hxf = HxCFunc.from_addr(func.ea)
                hxf.visit_cnode_filterlist(_call_node_callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e, exc_info=True)

            # Refresh Hex-Rays pseudocode.
            vdui = ida_hexrays.open_pseudocode(func.ea, ida_hexrays.OPF_REUSE)
            if vdui:
                vdui.refresh_view(True)

    @staticmethod
    def get_variable_name(node):
        try:
            # Works if the the node is a local variable.
            return node.lvar_name
        except AttributeError:
            # Works if the node is a pointer to a constant string.
            try:
                return brick_utils.get_wstring(node.ignore_cast.value)
            except:
                # Fallback, probably an expression such as &VariableName.
                return node.cstr

    def collect_GetSetVariable_calls(self):

        def callback(cn):
            if "->GetVariable" in cn.cstr or '->SmmGetVariable' in cn.cstr:
                self.GetVariable_calls.append(cn)

            if "->SetVariable" in cn.cstr or '->SmmSetVariable' in cn.cstr:
                self.SetVariable_calls.append(cn)

        for func in BipFunction.iter_all():
            try:
                hxf = HxCFunc.from_addr(func.ea)
                hxf.visit_cnode_filterlist(callback, [CNodeExprCall])
            except Exception as e:
                self.logger.debug(e, exc_info=True)

    def process_GetVariable_calls(self):
        # Process calls to GetVariable()
        for call in self.GetVariable_calls:
            varname = self.get_variable_name(call.get_arg(0))
            if self.var_name_to_GetVariable.get(varname):
                # Variable was encountered before.
                self.var_name_to_GetVariable[varname].extend([call.hxcfunc.ea])
            else:
                # First time.
                self.var_name_to_GetVariable[varname] = [call.hxcfunc.ea]

    def process_SetVariable_calls(self):
        # Process calls to SetVariable()
        for call in self.SetVariable_calls:
            varname = self.get_variable_name(call.get_arg(0))
            if not self.var_name_to_GetVariable.get(varname):
                # Variable was written without being fetched first, benign case.
                continue

            func_ea = call.hxcfunc.ea
            if func_ea not in self.var_name_to_GetVariable[varname]:
                # Function that sets the variable is differnet from the function that fetched it, probably benign.
                continue

            # If we got here, the function that sets the variable is the same as the function that reads it.
            # Now, we have to make sure the size argument passed to SetVariable is a constant integer greater than zero.
            varsize = call.get_arg(3)
            if isinstance(varsize, CNodeExprNum) and (varsize.value != 0):
                self.logger.warning(f'Variable {varname} is read by function 0x{func_ea:x} and then written again using constant size 0x{varsize.value:x}')

    def run(self):
        self.fix_SetVariable_prototype()
        self.collect_GetSetVariable_calls()
        self.process_GetVariable_calls()
        self.process_SetVariable_calls()
