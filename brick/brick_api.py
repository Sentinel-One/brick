from hunter import Hunter
from pathlib import Path

BRICK_IDA_PY = str(Path(__file__).parent / 'brick_ida.py')

def scan_file(filename, *modules) -> int:
    abspath = Path(filename).resolve()
    dirname = str(abspath.parent)
    basename = str(abspath.stem)

    hunter = Hunter(dirname, 64, '.efi', basename)
    hunter.analyze()
    hunter.cleanup()

    hunter.run_script(BRICK_IDA_PY, *modules)
    