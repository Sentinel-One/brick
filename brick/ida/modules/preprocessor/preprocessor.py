import ida_segment
import idc
import idaapi
import codatify

from bip.base import *
from ..base_module import BaseModule

class PreprocessorModule(BaseModule):

    def _set_text_section_rwx(self):
        text_section = ida_segment.get_segm_by_name('.text')
        if text_section:
            idc.set_segm_attr(text_section.start_ea, idc.SEGATTR_PERM, idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_EXEC)

    def _find_missing_functions(self):
        """
        Use codatify to find functions that the initial auto-analysis missed.
        """
        try:
            codatify.fix_code()
        except Exception:
            pass

        # Codatify sometimes does one of the following:
        # 1. Prepend int 3 instructions to the start of the function.
        # 2. Assemble a bunch of int 3 opcodes into their own function.
        # We attempt to fix these issues by re-creating some of the functions.
        for f in BipFunction.iter_all():
            new_ea = f.ea
            while new_ea < f.end and BipInstr(new_ea).bytes == [0xCC]: # int 3
                # Counts the number of int 3
                new_ea += 1
            
            if new_ea != f.ea:
                if new_ea == f.end:
                    # Delete 'functions' comprising entirely out of int 3 instructions.
                    idc.del_func(f.ea)
                else:
                    # Re-create functions 
                    idc.del_func(f.ea)
                    BipFunction.create(new_ea)

    def run(self):
        # Fix permissions for the code section
        self._set_text_section_rwx()
        # Find functions that the initial auto-analysis might have missed.
        self._find_missing_functions()