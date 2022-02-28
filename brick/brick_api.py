import pefile

from hunter import Hunter
from pathlib import Path

BRICK_IDA_PY = str(Path(__file__).parent / 'brick_ida.py')

def scan_file(filename, *modules) -> int:
    abspath = Path(filename).resolve()
    dirname = str(abspath.parent)
    basename = str(abspath.stem)
    extension = abspath.suffix

    smm_pe = pefile.PE(abspath)
    match smm_pe.FILE_HEADER.Machine:
        case pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_AMD64'):
            bitness = 64
        case pefile.MACHINE_TYPE.get('IMAGE_FILE_MACHINE_I386'):
            bitness = 32
        case _:
            raise ValueError(f'Unsupported machine type 0x{smm_pe.FILE_HEADER.Machine:x}')

    hunter = Hunter(dirname, bitness, extension, basename)
    hunter.analyze()
    hunter.cleanup()

    hunter.run_script(BRICK_IDA_PY, *modules)
    
def scan_directory(dirname, *modules) -> int:
    hunter = Hunter(dirname, 64, '.efi')
    hunter.analyze()
    hunter.cleanup()

    hunter.run_script(BRICK_IDA_PY, *modules)