from io import BytesIO, FileIO
import os
import subprocess
from .AbstractHarvester import AbstractHarvester
from logger import log_operation
import shutil
import os
from pathlib import Path
import subprocess
import glob

class UefiToolInfoFile:
    
    INFO_SUFFIX = '_info.txt'

    def __init__(self, path: str):
        if not path.endswith(self.INFO_SUFFIX):
            raise ValueError(f'Bad file suffix, expecting {self.INFO_SUFFIX}')

        self._path = path
        self._attrs = {}

        for line in open(path, 'r').read().splitlines():
            k, v = line.split(': ')
            self._attrs[k] = v

    def __getitem__(self, key):
        return self._attrs[key]

class UefiToolSmmInfoFile(UefiToolInfoFile):

    SMM_MODULE_PREFIX = 'File_SMM_module_'
    PE32_IMAGE_PREFIX = 'Section_PE32_image_'

    BODY_SUFFIX = '_body.bin'

    def __init__(self, path):
        if not Path(path).name.startswith(self.SMM_MODULE_PREFIX):
            raise ValueError(f'Bad file prefix, expecting {self.SMM_MODULE_PREFIX}')

        super().__init__(path)

    @property
    def pe32(self):
        """
        Returns the path of the corresponding PE32 image section.
        """
        pe32_section = self._path.replace(self.SMM_MODULE_PREFIX, self.PE32_IMAGE_PREFIX)
        pe32_section = pe32_section.replace(self.INFO_SUFFIX, self.BODY_SUFFIX)

        if not os.path.exists(pe32_section):
            raise FileNotFoundError(f'PE32 image {pe32_section} does not exist')

        return pe32_section

    @property
    def name(self):
        """
        Returns a friendly name if available, otherwise just returns the file's GUID.
        """
        try:
            return self['Text']
        except KeyError:
            return self['File GUID'].lower()


class UefiToolHarvester(AbstractHarvester):

    def __init__(self):
        super().__init__()
        self.uefi_extract_path = Path(__file__).parent.parent / 'bin' / 'UEFIExtract.exe'

    def _unpack(self, rom, clean=True):
        # By default UEFIExtract unpacks into the {rom}.dump directory
        unpack_dir = f'{rom}.dump'

        # UEFIExtract fails when the output directory already exists. 
        if os.path.exists(unpack_dir) and clean:
            shutil.rmtree(unpack_dir)
            
        subprocess.check_call([str(self.uefi_extract_path), rom, 'unpack'])
        return unpack_dir

    def _get_smm_executables(self, dirname):
        smm_executables = []
        smm_info_glob = f'{dirname}/File_SMM_module_*_info.txt'
        for smm_info_file in (UefiToolSmmInfoFile(_) for _ in glob.glob(smm_info_glob)):
            try:
                friendly_name = self.guids_dict[smm_info_file.name]
            except KeyError:
                friendly_name = smm_info_file.name
            smm_executables.append((friendly_name, smm_info_file.pe32))
        return smm_executables

    def iter(self, rom):
        dirname = self._unpack(rom)
        smm_executables = self._get_smm_executables(dirname)

        for name, pe32 in smm_executables:
            yield (name, FileIO(pe32, 'rb'))

        # No longer needed, so we can delete it.
        # shutil.rmtree(dirname)