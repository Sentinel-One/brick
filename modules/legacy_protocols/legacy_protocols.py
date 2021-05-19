import pathlib
parent = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(parent))
from base_module import BaseModule

import uuid
import pathlib
import sys
import pathlib
from contextlib import closing

# Hack to make 'guids_db' accessible.
root = pathlib.Path(__file__).resolve().parents[2]
sys.path.append(str(root))

# Load GUIDs database.
from guids_db import GuidsDatabase

from bip.base import *
import bip_utils

class LegacyProtocolsModule(BaseModule):

    def __init__(self) -> None:
        super().__init__()

    def _run(self):
        guids_filename = root / 'guids.csv'
        guids_db = GuidsDatabase(guids_filename)

        for guid, name in guids_db.legacy_guids.items():
            found = bip_utils.search_guid(guid)
            if found:
                # Report that a legacy GUID was found.
                self.logger.warning(f'Found legacy protocol {name} {guid} at 0x{found.ea:x}')

with closing(LegacyProtocolsModule()) as module:
    module.run()
    