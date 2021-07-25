import os
import pathlib
import argparse
from guids.guids_db import GuidsDatabase
from hunter import Hunter
import glob
from logger import log_step, log_operation, log_timing, log_warning
from modules import BRICK_MODULES_NAMES, BRICK_ODULES_DESCRIPTIONS
from harvest.utils import harvest
from yattag import Doc

def compact(outdir, outfile, clean=False):
    results = []

    for module in (pathlib.Path(module).resolve() for module in glob.glob(f'{outdir}\\*.efi')):
        try:
            report = module.with_suffix('.brick')
            data = open(report, 'r').read()
            results.append((str(module), data))
                
            if clean: os.remove(report)
        except Exception as e:
            log_warning(f'Failed processing {module}, exception {e}')
            continue
        
    COLORS = {
        'ERROR': 'red',
        'WARNING': 'orange',
        'SUCCESS': 'green',
        'INFO': 'purple'
    }

    doc, tag, text = Doc().tagtext()
    with tag('html'):
        with tag('body'):
            with tag('h1'):
                text(f'SUMMARY OF SCAN RESULTS')

        for x in results:
            with tag('table', border='2px solid black', style='width:100%'):
                with tag('tr'):
                    with tag('th', colspan='3'):
                        text(x[0])
                with tag('tr'):
                    with tag('td', colspan='3'):
                        with tag('ul'):
                            for line in x[1].splitlines():
                                level = line.split()[0]
                                color = COLORS.get(level, 'black')
                                with tag('li', style=f'color:{color}'):
                                    text(line)
                with tag('tr'):
                    with tag('td'):
                        text('IDA database: ')
                        idb = x[0].replace('.efi', '.i64')
                        with tag('a', href=idb):
                            text(idb)
                    with tag('td'):
                        text('IDA log: ')
                        log = x[0].replace('.efi', '.log')
                        with tag('a', href=log):
                            text(log)
                    with tag('td'):
                        text('efiXplorer log: ')
                        json = x[0].replace('.efi', '.json')
                        with tag('a', href=json):
                            text(json)
            with tag('br'):
                pass

    open(outfile, 'w').write(doc.getvalue())

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

    if modules is None:
        modules = BRICK_MODULES_NAMES

    bootstrap_script = pathlib.Path(__file__).parent / 'bootstrap.py'

    for mod in modules:
        with log_step(BRICK_ODULES_DESCRIPTIONS[mod]):
            hunter.run_script(bootstrap_script, mod)

    # Merge all individual output files into one report file, formatted as HTML.
    html_report = f'{rom}.html'
    with log_step('Compacting output files'):
        compact(outdir, html_report)

    return html_report

def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('rom', help='Path to firmware image to analyze')
    parser.add_argument('-o', '--outdir', help='Path to output directory')
    parser.add_argument('-m', '--modules', nargs='*', help='Module to execute (default: all)', choices=BRICK_MODULES_NAMES)
    parser.add_argument('-v', '--verbose', action='store_true', help='Use more verbose traces')
    
    args = parser.parse_args()
    if args.outdir is None:
        args.outdir = f'{args.rom}.output'

    with log_timing(f'Analyzing {args.rom}'):
        report = analyze(args.rom, args.outdir, args.modules, args.verbose)

    log_operation(f'Check the resulting report file at {report}')

if __name__ == '__main__':
    main()