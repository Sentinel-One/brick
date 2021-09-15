import os
from pathlib import Path
import tempfile
import subprocess
import idaapi
import copy
from externals import get_external
from .brick_utils import temp_env, temp_patch, set_directory, execfile
from contextlib import contextmanager
import sqlite3

DIAPHORA_DIR = get_external('diaphora')

def _export_this_idb(export_filename: str, **diaphora_kwargs: dict):
    with temp_env():
        os.environ['DIAPHORA_AUTO'] = '1'
        os.environ['DIAPHORA_EXPORT_FILE'] = export_filename

        os.environ.update(diaphora_kwargs)

        # Hook idaapi.qexit to avoid termination of the process.
        with temp_patch(idaapi, 'qexit', lambda code: None):
            with set_directory(DIAPHORA_DIR):
                new_globals = copy.copy(globals())
                new_globals['__file__'] = str(DIAPHORA_DIR / 'diaphora.py')
                new_globals['__name__'] = '__main__'
                execfile('diaphora.py', new_globals)

def export_this_idb(export_filename: str, use_decompiler=True, slow_heuristics=True):
    diaphora_kwargs = {}

    if use_decompiler:
        diaphora_kwargs['DIAPHORA_USE_DECOMPILER'] = '1'

    if slow_heuristics:
        diaphora_kwargs['DIAPHORA_SLOW_HEURISTICS'] = '1'

    _export_this_idb(export_filename, **diaphora_kwargs)

def calculate_diff(first: str, second: str, output_path: str=None) -> sqlite3.Connection:
    
    if output_path is None:
        (temp_fd, temp_name) = tempfile.mkstemp()
        os.close(temp_fd)
        output_path = temp_name

    with set_directory(DIAPHORA_DIR):
        args = ['python', 'diaphora.py', first, second, '-o', output_path]
        # print('Executing {}'.format(' '.join(args)))
        subprocess.check_call(args, creationflags=subprocess.CREATE_NO_WINDOW)
    
    return sqlite3.connect(output_path)
    
