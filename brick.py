import os
import pathlib
import argparse
from guids.guids_db import GuidsDatabase
from hunter import Hunter
import glob
from logger import log_step, log_operation, log_timing, log_warning
from modules import AVAILABLE_MODULE_NAMES, MODULE_DESCRIPTIONS
from harvest.utils import harvest
from yattag import Doc

def compact(outdir, outfile, clean=False):
    # Lists of SMM executables that:
    # passed: all checks completed successfully without issuing a warning
    # ignore: at least one check issued a warning, but that's probably a false positive that can be ignored
    # verify: at least one check issued a warning that might be a true positive.
    #         further manual analysis is required to further classify it as either true positive or false positive.
    passed, ignore, verify = [], [], []

    for module in (pathlib.Path(module) for module in glob.glob(f'{outdir}\\*.i64')):
        module = module.resolve()
        report = module.with_suffix('.brick')
        if os.path.exists(report):
            # At least one module issued a warning.
            data = open(report, 'r').read()
            # Unknown module (probably OEM-specific), might be a true positive.
            verify.append((str(module), data))
                
            if clean: os.remove(report)
        else:
            # No warnings.
            passed.append(str(module))
        
    COLORS = {
        'ERROR': 'red',
        'WARNING': 'orange',
        'INFO': 'green'
    }

    doc, tag, text = Doc().tagtext()
    with tag('html'):
        with tag('body'):
            with tag('h1'):
                text(f'SUMMARY OF SCAN RESULTS')

        for x in verify:
            i64 = x[0].replace('.efi', '.i64')
            with tag('a', href=i64):
                text(i64)
            with tag('ul'):
                for line in x[1].splitlines():
                    level = line.split()[0]
                    color = COLORS.get(level, 'black')
                    # with tag('p', )
                    with tag('li', style=f'color:{color}'):
                        text(line)
                # mdFile.write('<span style="color:blue">some *blue* text</span>')
                # mdFile.new_line(line)
            # bf.write(x[1])
        # print(mdFile.file_data_text)
    # html = markdown.markdown(mdFile.file_data_text)
    open('brick.html', 'w').write(doc.getvalue())

def main(rom, outdir, modules, verbose=False):
    # with log_step('Building GUIDs database'):
    #     db = GuidsDatabase()
    
    # with log_step('Harvesting SMM modules'):
    #     harvest(rom, outdir, db.guid2name)

    # # # 64-bit binaries with .efi extension
    # hunter = Hunter(outdir, 64, '.efi', verbose)

    # with log_step('Analyzing SMM modules'):
    #     hunter.analyze()

    # with log_step('Cleaning-up temporary files'):
    #     hunter.cleanup()

    # if modules is None:
    #     modules = AVAILABLE_MODULE_NAMES

    # bootstrap_script = pathlib.Path(__file__).parent / 'bootstrap.py'

    # for mod in modules:
    #     with log_step(MODULE_DESCRIPTIONS[mod]):
    #         hunter.run_script(bootstrap_script, mod)

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