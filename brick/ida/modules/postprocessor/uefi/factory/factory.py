from bip.hexrays import *

class UefiCallFactory:

    def __init__(self) -> None:
        self._creators = {}

    def register(self, name, cls):
        self._creators[name] = cls

    def get(self, cnode):
        for name, cls in self._creators.items():
            if '->' + name in cnode.cstr:
                return cls.from_cnode(cnode)

    def process_calls(self):

        def _apply_type_callback(cnode: CNode):
            call = self.get(cnode)
            if call is not None:
                call.set_call_type()

        def _process_call_callback(cnode: CNode):
            call = self.get(cnode)
            if call is not None:
                call.process()

        # 1st pass - apply correct prototype.
        for hxcfunc in HxCFunc.iter_all():
            hxcfunc.visit_cnode_filterlist(_apply_type_callback, [CNodeExprCall])
            hxcfunc.invalidate_cache()

        # 2nd pass - further process the call.
        for hxcfunc in HxCFunc.iter_all():
            hxcfunc.visit_cnode_filterlist(_process_call_callback, [CNodeExprCall])
            hxcfunc.invalidate_cache()