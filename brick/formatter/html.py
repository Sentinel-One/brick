from pathlib import Path
import glob
import os
from yattag import Doc
from logger import log_warning

def format(outdir, outfile, clean=False):
    results = []

    for module in (Path(module).resolve() for module in glob.glob(f'{outdir}\\*.efi')):
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
        'INFO': 'purple',
        'VERBOSE': 'teal',
        'HEADING': 'gray',
    }

    doc, tag, text = Doc().tagtext()
    with tag('html'):
        # with tag('script'):
        #     checkbox_script = Path(__file__).parent / 'checkbox.js'
        #     doc.asis(open(checkbox_script, 'r').read())

        with tag('body', onload='javascript:init()'):
            with tag('h1'):
                text(f'SUMMARY OF SCAN RESULTS')

        id = 0
        for x in results:
            with tag('table', border='2px solid black', style='width:100%'):
                with tag('tr'):
                    with tag('th', colspan='3'):
                        text(x[0])
                with tag('tr'):
                    with tag('td', colspan='3'):
                        with tag('ul'):
                            for line in x[1].splitlines():
                                id += 1
                                level = line.split()[0]
                                color = COLORS.get(level, 'black')
                                # if level == 'ERROR':
                                #     with tag('input', type='checkbox', id=f'checkbox_{id}', onchange=f'javascript:do_strikethrough(this, {id})'):
                                #         pass
                                with tag('li', id=f'li_{id}', style=f'color:{color}'):
                                    text(line)
                            
                with tag('tr'):
                    with tag('td'):
                        text('IDA database: ')
                        idb = x[0].replace('.efi', '.i64')
                        with tag('a', href=idb):
                            text(idb)
                    with tag('td'):
                        text('Raw IDA log: ')
                        log = x[0].replace('.efi', '.log')
                        with tag('a', href=log):
                            text(log)
                    with tag('td'):
                        text('efiXplorer report: ')
                        json = x[0].replace('.efi', '.json')
                        with tag('a', href=json):
                            text(json)
            with tag('br'):
                pass

    open(outfile, 'w').write(doc.getvalue())