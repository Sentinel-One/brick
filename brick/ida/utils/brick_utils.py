import uuid
from bip.base import *
from bip.hexrays import *
from alleycat import AlleyCat
from contextlib import contextmanager
import os
from pathlib import Path
import copy
import gorilla
import idaapi
import ida_loader
from ctypes import *


def get_paths(x, y, bidirectional=True):
    # Returns True iff there is a path between the two nodes.
    if x is None or y is None:
        return []

    print('x is', x, 'y is', y)

    if hasattr(x, 'ea'):
        ea1 = x.ea

    if ea1 == idaapi.BADADDR and hasattr(x, 'closest_ea'):
        ea1 = x.closest_ea

    if hasattr(y, 'ea'):
        ea2 = y.ea

    if ea2 == idaapi.BADADDR and hasattr(y, 'closest_ea'):
        ea2 = y.closest_ea

    print('x is', x, 'y is', y)
    paths = AlleyCat(ea1, ea2).paths
    
    # Paths are symmetric.
    if bidirectional:
        paths += AlleyCat(ea2, ea1).paths

    return paths

def path_exists(x, y):
    return bool(get_paths(x, y))

def set_indirect_call_type(ea, t):
    # standard call:
    # call    qword ptr [reg+off]
    # or tail call:
    # jmp     qword ptr [reg+off]
    instr = BipInstr(ea)
    assert instr.mnem in ('call', 'jmp'), f'Unexpected instruction {instr.mnem} at 0x{ea:x}'
    instr.op(0).type_info = t

@contextmanager
def set_directory(path: Path):
    """Sets the cwd within the context

    Args:
        path (Path): The path to the cwd

    Yields:
        None
    """

    origin = Path().absolute()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(origin)

@contextmanager
def temp_patch(destination, name, obj):
    settings = gorilla.Settings(allow_hit=True)
    patch = gorilla.Patch(destination, name, obj, settings)
    try:
        gorilla.apply(patch)
        yield
    finally:
        gorilla.revert(patch)

@contextmanager
def temp_env():
    original_env = copy.deepcopy(os.environ)
    try:
        yield
    finally:
        os.environ = original_env

try:
    from builtins import execfile
except (NameError, ImportError):
    def execfile(fn, globals=None, locals=None):
        return exec(open(fn).read(), globals, locals)

