import idc
from pathlib import Path

from edk2toollib.uefi.edk2.guid_list import GuidList

from bip.base import *
from ..base_module import BaseModule

class IsEdk2Module(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def run(self):
        edk2_dir = Path(__file__).parent / 'edk2'
        edk2_names = [n.name.lower() for n in GuidList.guidlist_from_filesystem(edk2_dir)]
        edk2_guids = [g.guid.lower() for g in GuidList.guidlist_from_filesystem(edk2_dir)]

        basename = Path(idc.get_input_file_path()).stem
        if basename.lower() in edk2_guids or basename.lower() in edk2_names:
            self.logger.info(f'{basename} is from EDK2, probably not vulnerable')
        else:
            self.logger.info(f'{basename} is not from EDK2, probably OEM specific')