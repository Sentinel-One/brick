# Load GUIDs database.
from guids.guids_db import GuidsDatabase

from bip.base import *

from ...utils import brick_utils, bip_utils
from ..base_module import BaseModule

from uuid import UUID

class LegacyProtocolsModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def trace_unknown_protocol_guids(self):
        for prop in BipElt.get_by_prefix('ProprietaryProtocol'):
            data = BipData.get_bytes(prop.ea, prop.size)
            try:
                guid = UUID(bytes_le=data)
            except ValueError:
                continue
            self.logger.debug(f'Found unknown protocol GUID {guid}')

    def run(self):
        guids_db = GuidsDatabase()
        
        for guid, name in guids_db.legacy_guids.items():
            found = bip_utils.search_guid(guid)
            if found:
                # Report that a legacy GUID was found.
                self.res = False
                self.logger.debug(f'Found legacy protocol {name} {guid} at 0x{found.ea:x}')

        if self.res:
            self.logger.success('No legacy protocols were found')

        self.trace_unknown_protocol_guids()