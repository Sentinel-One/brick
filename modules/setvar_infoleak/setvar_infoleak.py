import pathlib
import sys

parent = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(parent))
from base_module import BaseModule

import uuid
import pathlib
import sys
import pathlib
from contextlib import closing
import bip_utils
import functools

from bip.base import *
from bip.hexrays import *

g_get_variable_calls = []
g_set_variable_calls = []

# A dictionary that maps a variable name to a list of functions that called GetVariable() on it.
g_bookkeeping = {}

class SetVarInfoLeak(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def get_variable_name(node):
        try:
            # Works if the the node is a local variable.
            return node.lvar_name
        except AttributeError:
            # Works if the node is a pointer to a constant string.
            try:
                return bip_utils.get_wstring(node.ignore_cast.value)
            except:
                # Fallback, probably an expression such as &VariableName.
                return node.cstr

    @staticmethod
    def collect_GetSetVariable_calls():

        def callback(cn):
            if "->GetVariable" in cn.cstr:
                g_get_variable_calls.append(cn)

            if "->SetVariable" in cn.cstr:
                g_set_variable_calls.append(cn)

        for func in BipFunction.iter_all():
            try:
                hxf = HxCFunc.from_addr(func.ea)
                hxf.visit_cnode_filterlist(callback, [CNodeExprCall])
            except:
                continue

    def process_GetVariable_calls(self):
        # Process calls to GetVariable()
        for call in g_get_variable_calls:
            varname = self.get_variable_name(call.get_arg(0))
            if g_bookkeeping.get(varname):
                # Variable was encountered before.
                g_bookkeeping[varname].extend([call.hxcfunc.ea])
            else:
                # First time.
                g_bookkeeping[varname] = [call.hxcfunc.ea]

    def process_SetVariable_calls(self):
        # Process calls to SetVariable()
        for call in g_set_variable_calls:
            varname = self.get_variable_name(call.get_arg(0))
            if not g_bookkeeping.get(varname):
                # Variable was written without being fetched first, benign case.
                continue

            func_ea = call.hxcfunc.ea
            if func_ea not in g_bookkeeping[varname]:
                # Function that sets the variable is differnet from the function that fetched it, probably benign.
                continue

            # If we got here, the function that sets the variable is the same as the function that reads it.
            # Now, we have to make sure the size argument passed to SetVariable is a constant integer greater than zero.
            varsize = call.get_arg(3)
            if bip_utils.is_int_constant(varsize.cstr) and (varsize.value != 0):
                self.logger.warning(f'Variable {varname} is read by function 0x{func_ea:x} and then written again using constant size 0x{varsize.value:x}')

    def _run(self):
        self.collect_GetSetVariable_calls()
        self.process_GetVariable_calls()
        self.process_SetVariable_calls()

with closing(SetVarInfoLeak()) as module:
    module.run()
    