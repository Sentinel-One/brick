from bip.base import *
from bip.hexrays import *

def get_elt_by_prefix(prefix):
    return [f for f in BipElt.iter_all() if f.name.startswith(prefix)]

def return_type(hxcfunc):
    return hxcfunc.cstr.split()[0]
    