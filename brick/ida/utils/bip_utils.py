'''
Some utilities that wrap the functionality offered by Bip.
'''

from bip.hexrays import *

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
