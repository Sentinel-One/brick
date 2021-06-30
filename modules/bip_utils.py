import uuid
from bip.base import *
from alleycat import AlleyCat

def search_bytes(byt, min_ea=None, max_ea=None):
    if min_ea is None: min_ea = BipIdb.min_ea()
    if max_ea is None: max_ea = BipIdb.max_ea()
    
    byt = " ".join([hex(_) for _ in byt])
    return BipElt.search_bytes(byt, start_ea=min_ea, end_ea=max_ea, nxt=False)

def search_guid(guid, min_ea=None, max_ea=None):
    byt = uuid.UUID(guid).bytes_le
    return search_bytes(byt, min_ea, max_ea)

def get_wstring(ea):
    unicode_null = search_bytes(b'\x00' * 2, ea)
    if not unicode_null:
        return ''

    size = unicode_null.ea - ea
    wstr = BipData.get_bytes(ea, size).replace(b'\x00', b'')
    return wstr

def has_path(a, b):
    # Returns True iff there is a path between the two nodes.
    if hasattr(a, 'ea'):
        a = a.ea

    if hasattr(b, 'ea'):
        b = b.ea

    # Paths are symmetric.
    return AlleyCat(a, b).paths + AlleyCat(b, a).paths

def is_int_constant(cstr):
    for suffix in ('ui64', 'i64'):
        candidate = cstr.removesuffix(suffix)
        try:
            int(candidate, 0)
            return True
        except:
            continue

    return False