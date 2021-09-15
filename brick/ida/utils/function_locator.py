import tempfile
from . import diaphora_utils
from bip.base import *

import os
import rizzo

import idaapi
from pathlib import Path
from contextlib import closing
class FunctionRecognizer:
    
    def __init__(self, name, is_library=False):
        self.name = name
        self.is_library = is_library

    def _recognize(self, f: BipFunction):
        if f is not None:
            f.name = self.name
            f.is_lib = self.is_library

        return f

    def recognize_by_rizzo(self, sigdir):
        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

        return self._recognize(BipFunction.get_by_name(self.name))

    def recognize_by_heuristic(self, heur):
        for func in BipFunction.iter_all():
            if heur(func):
                return self._recognize(func)

    def recognize_by_diaphora(self, other: str, ratio:float=1.0):
        DIAPHORA_QUERY_FORMAT = 'SELECT name FROM results WHERE name2 = "{fname}" and CAST(ratio as FLOAT) > {ratio} ORDER by ratio DESC'

        # Use Diaphora to export the current .idb to a .sqlite database
        export_filename = str(Path(idaapi.get_input_file_path()).with_suffix('.sqlite'))
        diaphora_utils.export_this_idb(export_filename)

        # Find matching functions between the two modules.
        with closing(diaphora_utils.calculate_diff(export_filename, other)) as diff_results:
            cursor = diff_results.cursor()
            query = DIAPHORA_QUERY_FORMAT.format(fname=self.name, ratio=ratio)
            candidate = cursor.execute(query).fetchone()

        if candidate:
            return self._recognize(BipFunction.get_by_name(candidate[0]))
