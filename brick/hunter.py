from pathlib import Path
import subprocess
import multiprocessing
from logger import log_operation
from externals import get_external

class Hunter:

    IDAHUNT_DIR = get_external('idahunt')
    
    def __init__(self, dirname, arch, ext, verbose=False) -> None:
        self.dirname = dirname
        self.arch = arch
        self.ext = ext
        self.verbose = verbose
        self.max_ida = multiprocessing.cpu_count()
        self.version = 7.5

    def _run_idahunt(self, user_args):
        idahunt_main = str(self.IDAHUNT_DIR / 'idahunt.py')
        args = ['python', idahunt_main, '--inputdir', self.dirname, '--max-ida', str(self.max_ida), '--version', str(self.version)]
        
        if self.verbose:
            args.extend(['--verbose'])

        args.extend(user_args)
        log_operation('Executing {}'.format(' '.join(args)))
        
        return subprocess.check_call(args)

    def analyze(self):
        return self._run_idahunt(['--filter', fr"filters\names.py -a {self.arch} -e {self.ext} -v", '--analyse'])

    def cleanup(self):
        return self._run_idahunt(['--cleanup'])

    def run_script(self, script, *args):
        resolved = Path(script).resolve()
        if resolved.exists():
            # IDA Hunt prefers fully qualified paths.
            script = str(resolved)

        script_with_args = f'{script} ' + ' '.join(args)
        return self._run_idahunt(['--filter', fr"filters\names.py -a {self.arch} -e {self.ext} -v", '--scripts', script_with_args])
        
