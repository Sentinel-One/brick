from ...utils.ProtocolRecognizer import ProtocolRecognizer
from ...utils.FunctionLocator import FunctionRecognizer
from bip.base import *
from bip.hexrays import *
import ida_loader

from ...utils import brick_utils
from enum import IntEnum

class StopCNodeVisit(Exception):
    pass

class SmiHandler(BipFunction):
    
    class ValidationResult(IntEnum):
        SUCCESS = 0
        NO_ATTACK_SURFACE = 1
        CHECK_NESTED_POINTERS = 2
        HAS_NESTED_POINTERS = 4
        CHECK_POTENTIAL_OVERFLOW = 8
        NO_SMIS = 16

    def __init__(self, ea):
        super().__init__(ea=ea)

    @classmethod
    def iter_all(cls):
        for subcls in cls.__subclasses__():
            for smi in subcls.iter_all():
                yield smi

    def check_prototype(self):
        # Do some sanity checks on the arguments.
        if not (self.type.nb_args == 4 and \
                self.type.get_arg_name(0) == 'DispatchHandle' and \
                self.type.get_arg_name(1) == 'Context' and \
                self.type.get_arg_name(2) == 'CommBuffer' and \
                self.type.get_arg_name(3) == 'CommBufferSize'):
            return False

        return True

    def get_attack_surface(self):
        pass

    def validates_nested_pointers(self):
        AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = '{da473d7f-4b31-4d63-92b7-3d905ef84b84}'
        ASBVP_recognizer = ProtocolRecognizer(AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID, 'AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID', is_smm=True)

        ASBVP = ASBVP_recognizer.get().Instances
        SIBOSV = BipFunction.get_by_name('SmmIsBufferOutsideSmmValid')
        
        candidates = ASBVP + [SIBOSV]
        if any(brick_utils.path_exists(self, candidate) for candidate in candidates):
            return True

        return False

class LegacySwSmiHandler(SmiHandler):

    PREFIX = 'SwSmiHandler'

    @classmethod
    def iter_all(cls):
        for smi in (cls(f.ea) for f in BipFunction.get_by_prefix(cls.PREFIX)):
            if smi.check_prototype():
                yield smi

    def get_attack_surface(self):
        if self.can_decompile:

            def callback(cn):

                ea = None 

                if isinstance(cn, CNodeExprCall):
                    if any(x in cn.cstr for x in ('GetVariable', 'SmmGetVariable', 'ReadSaveState')):
                        # Calls one of {GetVariable, SmmGetVariable, ReadSaveState}.
                        ea = cn.ea

                if isinstance(cn, CNodeExprMemptr):
                    if 'CpuSaveState' in cn.cstr:
                        # Reads the SMM save state directly via gSmst->CpuSaveState[CpuIndex].
                        ea = cn.ea
                
                if brick_utils.path_exists(self, ea):
                    raise StopCNodeVisit()

            for hxcfunc in HxCFunc.iter_all():
                try:
                    hxcfunc.visit_cnode_filterlist(callback, [CNodeExprCall, CNodeExprMemptr])
                except StopCNodeVisit:
                    # An 'interesting' element was found via the Hex-Rays pseudocode.
                    return True

        return False

    def validate(self):
        res = SmiHandler.ValidationResult.SUCCESS

        if self.get_attack_surface():
            if not self.validates_nested_pointers():
                res |= SmiHandler.ValidationResult.CHECK_NESTED_POINTERS
        else:
            res |= SmiHandler.ValidationResult.NO_ATTACK_SURFACE

        return res


class CommBufferSmiHandler(SmiHandler):
    '''Represent an SMI handler that receives its arguments via the Communication Buffer.
    '''

    PREFIX = 'CbSmiHandler'

    def __init__(self, ea):
        super().__init__(ea)
        self._checks_comm_buffer_size = False

    @classmethod
    def iter_all(cls):
        for smi in (cls(f.ea) for f in BipFunction.get_by_prefix(cls.PREFIX)):
            if smi.check_prototype():
                yield smi

    def get_attack_surface(self):
        
        if self.can_decompile:
            self.hxcfunc.visit_cnode_filterlist
            # TODO: Search for xRefs to the arguments.
            hxcfunc = self.hxcfunc
            return hxcfunc.cstr.count('CommBuffer') > 2
        
        return None

    def _checks_comm_buff_size(self):

        def _callback(cnode):
            dereferenced = cnode.ops[0].ignore_cast
            if isinstance(dereferenced, CNodeExprVar):
                if dereferenced.lvar_name == 'CommBufferSize':
                    self._checks_comm_buff_size = True

        self._checks_comm_buff_size = False
        self.hxcfunc.visit_cnode_filterlist(_callback, [CNodeExprPtr])
        return self._checks_comm_buff_size

    def _has_nested_pointers(self):
        '''Does the CommBuffer contains nested pointers
        '''
        # Run type reconstruction for the Comm Buffer
        ida_loader.load_and_run_plugin('HexRaysCodeXplorer64', self.ea)

        hex_ea = hex(self.ea)[2:].lower()
        comm_buffer_type = BipType.from_c(f'CommBuffer_{hex_ea} *')
        
        # Set the type for the Comm Buffer
        comm_buffer_arg = self.hxcfunc.args[2]
        comm_buffer_arg.type = comm_buffer_type
        self.hxcfunc.invalidate_cache()
        
        # Check if the Comm Buffer has any nested pointers
        return any(isinstance(x, BTypePtr) for x in comm_buffer_type.children[0].children)

    def validate(self):
        res = SmiHandler.ValidationResult.SUCCESS

        if self.get_attack_surface():
            if not self.validates_nested_pointers():
                res |= SmiHandler.ValidationResult.CHECK_NESTED_POINTERS

            if self._has_nested_pointers():
                res |= SmiHandler.ValidationResult.HAS_NESTED_POINTERS

            if not self._checks_comm_buff_size():
                res |= SmiHandler.ValidationResult.CHECK_POTENTIAL_OVERFLOW
        else:
            res |= SmiHandler.ValidationResult.NO_ATTACK_SURFACE

        return res
