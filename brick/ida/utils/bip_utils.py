'''
Some utilities that wrap the functionality offered by Bip.
'''

from bip.base import *
from bip.hexrays import *

from uuid import UUID

def collect_cnode_filterlist(hxcfunc, user_callback, filter_list):
    matched_nodes = []

    def inner_callback(node):
        nonlocal matched_nodes
        if user_callback(node):
            matched_nodes.append(node)

    if hxcfunc is None:
        # Perform the search over all functions.
        for hxcfunc in HxCFunc.iter_all():
            hxcfunc.visit_cnode_filterlist(inner_callback, filter_list)
    else:
        hxcfunc.visit_cnode_filterlist(inner_callback, filter_list)

    return matched_nodes

def search_bytes(byt, min_ea=None, max_ea=None):
    if min_ea is None: min_ea = BipIdb.min_ea()
    if max_ea is None: max_ea = BipIdb.max_ea()
    
    byt = " ".join([hex(_) for _ in byt])
    return BipElt.search_bytes(byt, start_ea=min_ea, end_ea=max_ea, nxt=False)

def search_guid(guid, min_ea=None, max_ea=None):
    if not isinstance(guid, UUID):
        # Try converting to a UUID object first.
        guid = UUID(guid)

    return search_bytes(guid.bytes_le, min_ea, max_ea)
    