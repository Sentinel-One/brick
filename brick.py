from contextlib import closing
from harvest.NativePythonHarvester import NativePythonHarvester
from harvest.UefiToolHarvester import UefiToolHarvester
import os
import pathlib
import argparse
import shutil
from guids_db import GuidsDatabase
from hunter import Hunter
import glob
from logger import log_step, log_operation, log_timing, log_warning
from modules import AVAILABLE_MODULE_NAMES, MODULE_DESCRIPTIONS

GUIDS_FILENAME = 'guids.csv'

def harvest(rom, outdir, guids_dict=None):
    log_operation(f'Creating directory {outdir}')

    if os.path.exists(outdir):
        shutil.rmtree(outdir)

    os.mkdir(outdir)

    for cls in (NativePythonHarvester, UefiToolHarvester):
        log_operation(f'Trying to harvest SMM modules using {cls.__name__}')

        try:
            harvester = cls()
            harvester.ext = 'efi'
            harvester.guids_dict = guids_dict
            harvester.harvest(rom, outdir)
        except Exception as e:
            # Harvest was unsuccessful, fall back into other harvesters in case there are any.
            log_warning(f'Harvest of SMM modules using {cls.__name__} failed, {e}')
            continue

        if os.listdir(outdir):
            # Harvest was successful.
            break
        else:
            # Harvest was unsuccessful, fall back into other harvesters in case there are any.
            log_warning(f'Harvest of SMM modules using {cls.__name__} failed')
            continue

def compact(outdir, outfile, clean=False):
    # Lists of SMM executables that:
    # passed: all checks completed successfully without issuing a warning
    # ignore: at least one check issued a warning, but that's probably a false positive that can be ignored
    # verify: at least one check issued a warning that might be a true positive.
    #         further manual analysis is required to further classify it as either true positive or false positive.
    passed, ignore, verify = [], [], []

    for module in (pathlib.Path(module) for module in glob.glob(f'{outdir}\\*.efi')):
        report = module.with_suffix('.brick')
        if os.path.exists(report):
            # At least one module issued a warning.
            data = open(report, 'r').read()
            basename = module.stem.lower()
            # Unknown module (probably OEM-specific), might be a true positive.
            verify.append((str(module), data))
                
            if clean: os.remove(report)
        else:
            # No warnings.
            passed.append(str(module))
        
    with open(outfile, 'w') as bf:
        bf.write('*' * 50 + ' SUMMARY ' + '*' * 50)
        bf.write('\n')

        for x in verify:
            bf.write('''
[*] --------------------------------------------------
[*] {}
[*] --------------------------------------------------'''.format(x[0]))
            bf.write('\n')
            bf.write(x[1])

def main(rom, outdir, modules, verbose=False):
    with log_step('Building GUIDs database'):
        db = GuidsDatabase(GUIDS_FILENAME)
    
    with log_step('Harvesting SMM modules'):
        harvest(rom, outdir, db.guid2name)

    # # 64-bit binaries with .efi extension
    hunter = Hunter(outdir, 64, '.efi', verbose)

    with log_step('Analyzing SMM modules'):
        hunter.analyze()

    with log_step('Cleaning-up temporary files'):
        hunter.cleanup()

    if modules is None:
        modules = AVAILABLE_MODULE_NAMES

    bootstrap_script = pathlib.Path(__file__).parent / 'bootstrap.py'

    for mod in modules:
        with log_step(MODULE_DESCRIPTIONS[mod]):
            hunter.run_script(bootstrap_script, mod)

    # Merge all individual output files into one file.
    with log_step('Compacting output files'):
        compact(outdir, f'{rom}.brick')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument('rom', help='Path to firmware image to analyze')
    parser.add_argument('-o', '--outdir', default='output', help='Path to output directory')
    parser.add_argument('-m', '--modules', nargs='*', help='Module to execute (default: all)', choices=AVAILABLE_MODULE_NAMES)
    parser.add_argument('-v', '--verbose', action='store_true', help='Use more verbose traces')
    
    args = parser.parse_args()

    with log_timing(f'Analyzing {args.rom}'):
        main(args.rom, args.outdir, args.modules, args.verbose)

    log_operation(f'Check the resulting output file at {args.rom}.brick')