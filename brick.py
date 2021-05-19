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
from logger import BrickFormatter, log_step, log_operation, log_timing, log_warning
from edk2toollib.uefi.edk2.guid_list import GuidList

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
        except:
            # Harvest was unsuccessful, fall back into other harvesters in case there are any.
            log_warning(f'Harvest of SMM modules using {cls.__name__} failed')
            continue

        if os.listdir(outdir):
            # Harvest was successful.
            break
        else:
            # Harvest was unsuccessful, fall back into other harvesters in case there are any.
            log_warning(f'Harvest of SMM modules using {cls.__name__} failed')
            continue

def compact(outdir, outfile, edk2dir=None, clean=True):
    if edk2dir:
        known_names = [x.name.lower() for x in GuidList.guidlist_from_filesystem(edk2dir)]
        known_guids = [x.guid.lower() for x in GuidList.guidlist_from_filesystem(edk2dir)]
    else:
        known_names = []
        known_guids = []

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
            if (basename in known_names) or (basename in known_guids):
                # Comes from EDK2, so likely to be a false positive.
                ignore.append((str(module), data))
            else:
                # Unknown module (probably OEM-specific), might be a true positive.
                verify.append((str(module), data))
                
            if clean: os.remove(report)
        else:
            # No warnings.
            passed.append(str(module))
        
    with closing(BrickFormatter(outfile)) as bf:
        bf.write('*' * 50 + ' SUMMARY ' + '*' * 50)
        bf.write()

        bf.write_section_header("Might be true positives")
        for x in verify:
            bf.write_entry(x[0], x[1])
            bf.write()

        bf.write_section_header("Likely to be false positives")
        for x in ignore:
            bf.write_entry(x[0], x[1])
            bf.write()

        bf.write_section_header("No vulnerabilities found")
        for x in passed:
            bf.write_entry(x)

def main(rom, outdir, module):
    with log_step('Building GUIDs database'):
        db = GuidsDatabase(GUIDS_FILENAME)
    
    with log_step('Harvesting SMM modules'):
        harvest(rom, outdir, db.guid2name)

    # # 64-bit binaries with .efi extension
    hunter = Hunter(outdir, 64, '.efi')

    with log_step('Analyzing SMM modules'):
        hunter.analyze()

    with log_step('Cleaning-up temporary files'):
        hunter.cleanup()

    # Analyze the modules with efiXplorer.
    with log_step('Applying efiXplorer'):
        hunter.run_script('modules/efiXplorer/apply_efiXplorer.py')

    # Scan for functions which have explicit handling for CSEG memory.
    with log_step('Scanning for CSEG-related functions'):
        hunter.run_script('modules/cseg/scan_cseg.py')

    # Check for SMM modules which might use legacy protocols.
    with log_step('Scanning for legacy protocols'):
        hunter.run_script('modules/legacy_protocols/legacy_protocols.py')

    # Check for missing calls to SmmIsBufferOutsideSmmValid()
    with log_step('Scanning for missing calls to SmmIsBufferOutsideSmmValid()'):
        hunter.run_script('modules/buffer_outside_smm/check_buffer_outside_smm.py')

    with log_step('Scanning for calls to SetVariable() which might leak SMRAM data'):
        hunter.run_script('modules/setvar_infoleak/setvar_infoleak.py')

    # Merge all individual output files into one file.
    with log_step('Compacting output files'):
        compact(outdir, f'{rom}.brick', 'edk2')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument('rom', help='Path to firmware image to analyze')
    parser.add_argument('-o', '--outdir', default='output', help='Path to output directory')
    parser.add_argument('-m', '--module', default='*', help='The module to execute (default: all)')
    
    args = parser.parse_args()

    with log_timing(f'Analyzing {args.rom}'):
        main(args.rom, args.outdir, args.module)

    log_operation(f'Please check the resulting output file at {args.rom}.brick')