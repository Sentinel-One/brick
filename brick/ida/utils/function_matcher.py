import tempfile
from . import diaphora_utils
from bip.base import *

import os
import rizzo
import fingermatch

import idaapi
from pathlib import Path
from contextlib import closing

class FunctionMatcher:
    '''
    Recognizes functions in a binary using several different tools and techniques.
    '''
    
    def __init__(self, name, is_library=False):
        self.name = name
        self.is_library = is_library

    def _do_match(self, f: BipFunction):
        '''
        Called when a match is detected.
        '''

        if f is not None:
            f.name = self.name
            f.is_lib = self.is_library

        return f

    def match_by_rizzo(self, sigdir):
        '''
        Recognizes a function using Rizzo.
        See https://github.com/tacnetsol/ida/tree/master/plugins/rizzo for more details.
        '''

        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

        return self._do_match(BipFunction.get_by_name(self.name))

    def match_by_fingermatch(self, fingermatch_db):
        '''
        Recognizes a function using FingerMatch.
        See https://github.com/jendabenda/fingermatch for more details.
        '''
        
        matches = fingermatch.fingermatch_match(fingermatch_db, apply_matched=False)
        func = next((match.ea[0] for match in matches if match.name == self.name), None)
        if func:
            return self._do_match(BipFunction(func))

    def match_by_heuristic(self, heur, decompiler_required=False):
        '''
        Recognizes a function using a caller provided heuristic function.
        '''

        for func in BipFunction.iter_all():

            if decompiler_required and not func.can_decompile:
                # The heuristic function relies on the decompiler but for some reason decompilation failed.
                continue

            if heur(func):
                return self._do_match(func)

    def match_by_diaphora(self, other: str, ratio:float=1.0):
        '''
        Recognizes a function using the binary diffing capabilities offered by Diaphora.
        See https://github.com/joxeankoret/diaphora for more details.
        '''

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
            return self._do_match(BipFunction.get_by_name(candidate[0]))
