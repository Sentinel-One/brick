# Load GUIDs database.
from guids.guids_db import GuidsDatabase

from bip.base import *
import brick_utils

from ..base_module import BaseModule

class LegacyProtocolsModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def run(self):
        guids_db = GuidsDatabase()
        
        has_legacy = False
        for guid, name in guids_db.legacy_guids.items():
            found = brick_utils.search_guid(guid)
            if found:
                # Report that a legacy GUID was found.
                has_legacy = True
                self.logger.warning(f'Found legacy protocol {name} {guid} at 0x{found.ea:x}')

        if not has_legacy:
            self.logger.info('No legacy protocols were found')
