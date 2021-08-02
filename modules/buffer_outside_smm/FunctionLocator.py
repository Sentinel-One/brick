from bip.base import *

import os
import rizzo

class FunctionRecognizer:
    
    def __init__(self, name):
        self.name = name

    def recognize_by_signature(self, sigdir):
        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

    def recognize_by_heuristic(self, heur):
        for func in BipFunction.iter_all():
            if heur(func):
                func.name = self.name

    def get(self):
        return BipFunction.get_by_name(self.name)
