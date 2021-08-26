import uuid
import shutil
from .AbstractHarvester import AbstractHarvester

from logger import log_operation
from pathlib import Path
import pefile

class SingleFileHarvester(AbstractHarvester):
    """
    A 'pseudo-harvester' which operates on a single file.
    """
    
    def harvest(self, rom, outdir):

        try:
            pefile.PE(rom)
        except pefile.PEFormatError:
            raise
        else:
            # The ROM file is actually a SMM PE.
            smm_pe = rom

        basename = Path(smm_pe).stem
        try:
            # Check if the basename is a valid GUID.
            uuid.UUID(basename)
        except ValueError:
            # Not a valid UUID, use the basename as is.
            friendly_name = basename
        else:
            # Valid UUID, try to get the corresponding friendly name.
            friendly_name = self.guid2name(basename)
        
        smm_mod_path = Path(outdir) / friendly_name
        if self.ext:
            smm_mod_path = smm_mod_path.with_suffix(f'.{self.ext}')

        log_operation(f'Dumping {friendly_name} to disk')
        shutil.copy(rom, smm_mod_path)
