import pathlib
import argparse

from progressbar.bar import ProgressBar
from guids.guids_db import GuidsDatabase
from hunter import Hunter
from logger import log_step, log_operation, log_timing
from ida.modules import BRICK_FULL_RUN_MODULES, BRICK_QUICK_RUN_MODULES, BRICK_MODULES_DESCRIPTIONS
from harvest.utils import do_harvest
from formatter.html import format
import progressbar
import threading
import harvest.filters
from multiprocessing.connection import Listener
from shared import NOTIFICATION_ADDRESS

def update_progress_bar(max_value: int):
    
    listener = Listener(NOTIFICATION_ADDRESS)
    bar = progressbar.ProgressBar(max_value=max_value)

    while True:
        # When the analysis is complete, the client is expected to connect to the server.
        # We use it as an indication we should update the progress bar.
        listener.accept()
        bar.update(bar.value + 1)

def analyze(rom, outdir, modules, verbose=False, quick=False):
    with log_step('Building GUIDs database'):
        db = GuidsDatabase()
    
    with log_step('Harvesting SMM modules'):
        filter = harvest.filters.skip_edk2_filter if quick else None
        do_harvest(rom, outdir, db.guid2name, filter)

    # 64-bit binaries with .efi extension
    hunter = Hunter(outdir, 64, '.efi', verbose)

    with log_step('Analyzing SMM modules'):
        hunter.analyze()

    with log_step('Cleaning-up temporary files'):
        hunter.cleanup()

    bootstrap_script = pathlib.Path(__file__).parent / 'brick_ida.py'

    import glob
    max_value = len(glob.glob(f"{outdir}\\*.efi"))
    # Start a background thread to update the progess bar when 
    threading.Thread(target=update_progress_bar, args=(max_value, ), daemon=True).start()

    hunter.run_script(bootstrap_script)

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
    parser.add_argument('-q', '--quick', action='store_true', help='Skip EDK2 binaries')

    modules_group = parser.add_mutually_exclusive_group()
    modules_group.add_argument('-m', '--modules',
                               nargs='*',
                               help='Explicitly specify the modules to execute (default: all)',
                               choices=BRICK_FULL_RUN_MODULES,
                               default=BRICK_FULL_RUN_MODULES)
    
    args = parser.parse_args()
    if args.outdir is None:
        args.outdir = f'{args.rom}.output'

    with log_timing(f'Analyzing {args.rom}'):
        report = analyze(args.rom, args.outdir, args.modules, args.verbose, args.quick)

    log_operation(f'Check the resulting report file at {report}')

if __name__ == '__main__':
    main()