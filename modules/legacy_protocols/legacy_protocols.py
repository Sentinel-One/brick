# Load GUIDs database.
from guids.guids_db import GuidsDatabase

from bip.base import *

from .. import brick_utils
from ..base_module import BaseModule

class LegacyProtocolsModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def run(self):
        guids_db = GuidsDatabase()
        
        for guid, name in guids_db.legacy_guids.items():
            found = brick_utils.search_guid(guid)
            if found:
                # Report that a legacy GUID was found.
                self.res = False
                self.logger.warning(f'Found legacy protocol {name} {guid} at 0x{found.ea:x}')

        if self.res:
            self.logger.success('No legacy protocols were found')
