from .Differ import Diaphora
from bip.base import *

import os
import rizzo
import sqlite3
class FunctionRecognizer:
    
    def __init__(self, name, is_library=False):
        self.name = name
        self.is_library = is_library

    def recognize_by_signature(self, sigdir):
        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

        f = self.get()
        if f:
            f.is_lib = self.is_library

    def recognize_by_heuristic(self, heur):
        for func in BipFunction.iter_all():
            if heur(func):
                func.name = self.name
                func.is_lib = self.is_library

    def recognize_by_diaphora(self, other, ratio):
        diaphora = Diaphora()
        diaphora.export_this_idb()
        diff_db = diaphora.calculate_diff(other)
        print(diff_db)
        conn = sqlite3.connect(diff_db)
        cursor = conn.cursor()
        results = cursor.execute(f'SELECT name FROM results WHERE name2 = "{self.name}" and CAST(ratio as FLOAT) > {ratio} ORDER by ratio DESC')
        # Best result
        candidate = results.fetchone()
        print('candidate func is ', candidate)
        if candidate:
            func = BipFunction.get_by_name(candidate[0])
            func.name = self.name
            func.is_lib = self.is_library

    def get(self):
        return BipFunction.get_by_name(self.name)
