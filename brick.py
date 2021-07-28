import pathlib
import argparse
from guids.guids_db import GuidsDatabase
from hunter import Hunter
from logger import log_step, log_operation, log_timing, log_warning
from modules import BRICK_FULL_RUN_MODULES, BRICK_QUICK_RUN_MODULES, BRICK_MODULES_DESCRIPTIONS
from harvest.utils import harvest
from formatter.html import format

def analyze(rom, outdir, modules, verbose=False):
    with log_step('Building GUIDs database'):
        db = GuidsDatabase()
    
    with log_step('Harvesting SMM modules'):
        harvest(rom, outdir, db.guid2name)

    # 64-bit binaries with .efi extension
    hunter = Hunter(outdir, 64, '.efi', verbose)

    with log_step('Analyzing SMM modules'):
        hunter.analyze()

    with log_step('Cleaning-up temporary files'):
        hunter.cleanup()

    bootstrap_script = pathlib.Path(__file__).parent / 'bootstrap.py'

    for mod in modules:
        with log_step(BRICK_MODULES_DESCRIPTIONS[mod]):
            hunter.run_script(bootstrap_script, mod)

    # Merge all individual output files into one report file, formatted as HTML.
    html_report = f'{rom}.html'
    with log_step('Formatting output files'):
        format(outdir, html_report)

    return html_report

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('rom', help='Path to firmware image to analyze')
    parser.add_argument('-o', '--outdir', help='Path to output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Use more verbose traces')

    modules_group = parser.add_mutually_exclusive_group()
    modules_group.add_argument('-m', '--modules', nargs='*', help='Module to execute (default: all)', choices=BRICK_FULL_RUN_MODULES, default=BRICK_FULL_RUN_MODULES)
    modules_group.add_argument('-q', '--quick', action='store_const', const=BRICK_QUICK_RUN_MODULES, dest='modules', help='Execute only a predefined set of modules')
    
    args = parser.parse_args()
    if args.outdir is None:
        args.outdir = f'{args.rom}.output'

    with log_timing(f'Analyzing {args.rom}'):
        report = analyze(args.rom, args.outdir, args.modules, args.verbose)

    log_operation(f'Check the resulting report file at {report}')

if __name__ == '__main__':
    main()