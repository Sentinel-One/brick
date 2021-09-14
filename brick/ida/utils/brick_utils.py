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

def search_bytes(byt, min_ea=None, max_ea=None):
    if min_ea is None: min_ea = BipIdb.min_ea()
    if max_ea is None: max_ea = BipIdb.max_ea()
    
    byt = " ".join([hex(_) for _ in byt])
    return BipElt.search_bytes(byt, start_ea=min_ea, end_ea=max_ea, nxt=False)

def search_guid(guid, min_ea=None, max_ea=None):
    if not isinstance(guid, uuid.UUID):
        # Try converting to a UUID object first.
        guid = uuid.UUID(guid)

    return search_bytes(guid.bytes_le, min_ea, max_ea)

def get_wstring(ea):
    unicode_null = search_bytes(b'\x00' * 2, ea)
    if not unicode_null:
        return ''

    size = unicode_null.ea - ea
    wstr = BipData.get_bytes(ea, size).replace(b'\x00', b'')
    return wstr

def get_paths(x, y, bidirectional=True):
    # Returns True iff there is a path between the two nodes.
    if (x is None) or (y is None):
        return []

    if hasattr(x, 'ea'):
        x = x.ea

    if hasattr(y, 'ea'):
        y = y.ea

    paths = AlleyCat(x, y).paths
    
    # Paths are symmetric.
    if bidirectional:
        paths += AlleyCat(y, x).paths

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
except NameError:
    def execfile(fn, globals=None, locals=None):
        return exec(open(fn).read(), globals, locals)

