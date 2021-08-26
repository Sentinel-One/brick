import shutil
from logger import log_operation
import os
import uefi_firmware
from pathlib import Path

from .AbstractHarvester import AbstractHarvester

class NativePythonHarvester(AbstractHarvester):

    SECTION_TYPE_PE_32 = 0x10
    SECTION_TYPE_UI    = 0x15

    def harvest(self, rom, outdir):
        file_content = open(rom, 'rb').read()
        parser = uefi_firmware.AutoParser(file_content)
        # uefi_firmware.MultiVolumeContainer
        firmware = parser.parse()
        try:
            bios = firmware.regions[0]
            assert bios.name == "bios"
        except AttributeError:
            bios = firmware
        
        objects = uefi_firmware.utils.flatten_firmware_objects(bios.iterate_objects())
        smm = [obj for obj in objects if obj['attrs'].get('type_name') == 'system management']
        # smm = [obj for obj in objects if obj['attrs'].get('type_name') == 'system.management']
        for module in smm:
            sections = module['_self'].objects
            friendly_name = None
            content = None

            for section in sections:
                if section.type == self.SECTION_TYPE_PE_32:
                    content = section.data
                if section.type == self.SECTION_TYPE_UI:
                    friendly_name = str(section.data, 'utf-16').replace("\x00", "")

            if friendly_name is None:
                # No UI section, fall back into querying the GUIDs database.
                friendly_name = self.guid2name(section.guid_label)

            smm_mod_path = Path(outdir) / friendly_name
            if self.ext:
                smm_mod_path = smm_mod_path.with_suffix(f'.{self.ext}')
                
            log_operation(f'Dumping {friendly_name} to disk')
            open(smm_mod_path, 'wb').write(content)