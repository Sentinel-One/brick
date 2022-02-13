import ida_segment
import idc
import idaapi
import codatify
import ida_typeinf

from pathlib import Path
from bip.base import *
from ..base_module import BaseModule
from externals import get_external

class PreprocessorModule(BaseModule):

    DEPENDS_ON = []

    UEFI_C_MACROS = {
        'EFIAPI': '__stdcall',
        'IN': '',
        'OUT': '',
        'OPTIONAL': '',
        'CONST': 'const',
        'PACKED': '',
    }

    def __init__(self) -> None:
        super().__init__()
        self.include_dir = Path(__file__).parent / 'include'
        self.edk2 = get_external('edk2')

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

    def define_uefi_macros(self):
        macros = ida_typeinf.get_c_macros()
        for key, value in self.UEFI_C_MACROS.items():
            macros += f'{key}={value};'
        ida_typeinf.set_c_macros(macros)

    def load_protocol_definitions(self):
        self.define_uefi_macros()

        # Custom includes
        for header in self.include_dir.iterdir():
            BipType.import_c_header(str(header))

        # EDK2 includes
        header_path = ida_typeinf.get_c_header_path()
        for include_dir in self.edk2.rglob('*/Include'):
            if not include_dir.is_dir():
                continue
            header_path += f";{include_dir.as_posix()}"
        ida_typeinf.set_c_header_path(header_path)

        for include in self.edk2.rglob('Include/Protocol/*.h'):
            ret = BipType.import_c_header(str(include))
            print(f'Loading {str(include)}: {ret}')

    def run(self):
        # Fix permissions for the code section
        self._set_text_section_rwx()
        # Find functions that the initial auto-analysis might have missed.
        self._find_missing_functions()
        self.load_protocol_definitions()