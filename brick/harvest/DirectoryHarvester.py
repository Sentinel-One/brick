from .AbstractHarvester import AbstractHarvester

import os
from pathlib import Path
from uuid import UUID
from logger import log_operation
import shutil
import pefile

class DirectoryHarvester(AbstractHarvester):
    """
    A 'pseudo-harvester' which operates on a directory.
    """
    
    def iter(self, rom):

        if not os.path.isdir(rom):
            raise RuntimeError(f'{rom} is not a directory')
        
        # The "ROM" file is actually a directory.
        indir = rom

        for infile in Path(indir).iterdir():

            try:
                pefile.PE(infile)
            except pefile.PEFormatError:
                # Not a PE file.
                continue

            basename = infile.stem

            try:
                # Check if the basename is a valid GUID.
                UUID(basename)
            except ValueError:
                # Not a valid UUID, use the basename as is.
                friendly_name = basename
            else:
                # Valid UUID, try to get the corresponding friendly name.
                friendly_name = self.guid2name(basename)
        
            yield (friendly_name, open(infile, 'rb'))
            # smm_mod_path = Path(outdir) / friendly_name
            # if self.ext:
            #     smm_mod_path = smm_mod_path.with_suffix(f'.{self.ext}')

            # log_operation(f'Dumping {friendly_name} to disk')
            # shutil.copy(infile, smm_mod_path)
