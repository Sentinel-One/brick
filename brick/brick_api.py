import pefile

from hunter import Hunter
from pathlib import Path

BRICK_IDA_PY = str(Path(__file__).parent / 'brick_ida.py')

def scan_file(filename, *modules) -> int:
    abspath = Path(filename).resolve()
    dirname = str(abspath.parent)
    basename = str(abspath.stem)
    extension = abspath.suffix

    machine = pefile.PE(abspath).FILE_HEADER.Machine
    if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        bitness = 64
    elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        bitness = 32
    else:
        raise ValueError(f'Unsupported machine type 0x{machine:x}')

    hunter = Hunter(dirname, bitness, extension, basename)
    hunter.analyze()
    hunter.cleanup()

    hunter.run_script(BRICK_IDA_PY, *modules)
    
def scan_directory(dirname, *modules) -> int:
    hunter = Hunter(dirname, 64, '.efi')
    hunter.analyze()
    hunter.cleanup()

    hunter.run_script(BRICK_IDA_PY, *modules)