import uuid
from bip.base import *
from alleycat import AlleyCat

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

def path_exists(x, y):
    # Returns True iff there is a path between the two nodes.
    if (x is None) or (y is None):
        return False

    if hasattr(x, 'ea'):
        x = x.ea

    if hasattr(y, 'ea'):
        y = y.ea

    # Paths are symmetric.
    return bool(AlleyCat(x, y).paths + AlleyCat(y, x).paths)

def set_indirect_call_type(ea, t):
    # call    qword ptr [reg+off]
    instr = BipInstr(ea)
    assert instr.mnem == 'call'
    instr.op(0).type_info = t
