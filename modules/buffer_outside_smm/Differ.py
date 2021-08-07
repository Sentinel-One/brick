import os
from pathlib import Path
import tempfile
import subprocess
import idaapi
import copy

from ..brick_utils import temp_env, temp_patch, set_directory

try:
    execfile
except NameError:
    def execfile(fn, globals=None, locals=None):
        return exec(open(fn).read(), globals, locals)

class Diaphora:

    DIAPHORA_PATH = r'C:\Users\carlsbad\Code\diaphora\diaphora.py'

    def __init__(self) -> None:
        self.export_filename = Path(idaapi.get_input_file_path()).with_suffix('.sqlite')
        
    def export_this_idb(self, use_decompiler=True, slow_heuristics=True):
        with temp_env():
            os.environ['DIAPHORA_AUTO'] = '1'
            os.environ['DIAPHORA_EXPORT_FILE'] = str(self.export_filename)

            if use_decompiler:
                os.environ['DIAPHORA_USE_DECOMPILER'] = '1'

            if slow_heuristics:
                os.environ['DIAPHORA_SLOW_HEURISTICS'] = '1'

            with temp_patch(idaapi, 'qexit', lambda code: None):
                with set_directory(r"C:\Users\carlsbad\Code\diaphora"):
                    new_globals = copy.copy(globals())
                    new_globals['__file__'] = os.path.join(os.getcwd(), 'diaphora.py')
                    new_globals['__name__'] = '__main__'
                    execfile(r"diaphora.py", new_globals)

    def calculate_diff(self, other):
        (temp_fd, temp_name) = tempfile.mkstemp()
        os.close(temp_fd)
        temp_name += ".sqlite"

        with set_directory(r"C:\Users\carlsbad\Code\diaphora"):
            args = ['python', r"diaphora.py", str(self.export_filename), other, '-o', temp_name]
            # print('Executing {}'.format(' '.join(args)))
            subprocess.check_call(args)
        return temp_name
