import idaapi
from ctypes import *
import ida_loader

class HexRaysCodeXplorerError(RuntimeError):
    pass

class TypeReconstructor:

    def __init__(self) -> None:
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            self.plugin = 'HexRaysCodeXplorer64'
            self.ea_t = c_uint64
        else:
            self.plugin = 'HexRaysCodeXplorer'
            self.ea_t = c_uint32

    def reconstruct_type(self, func_ea: int, var_name: str, var_type: str):

        var_name = bytes(var_name, 'ascii')
        var_type = bytes(var_type, 'ascii')

        class reconstruct_type_params_t(Structure):
            _fields_ = [
                ('func_ea', self.ea_t),
                ('var_name', c_char * 100),
                ('var_type', c_char * 100)
            ]

        reconstruct_type_params = reconstruct_type_params_t(func_ea, var_name, var_type)
        rc = ida_loader.load_and_run_plugin(self.plugin, addressof(reconstruct_type_params))
        if not rc:
            raise HexRaysCodeXplorerError(f'HexRaysCodeXplorer failed to reconstruct structure for variable {var_name} at 0x{func_ea:x}')
            