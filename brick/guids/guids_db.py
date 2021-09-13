import csv
import functools
from pathlib import Path
from uuid import UUID

DEFAULT_GUIDS_FILENAME = Path(__file__).parent / 'guids.csv'

class GuidsDatabase:

    def __init__(self, filename=DEFAULT_GUIDS_FILENAME):
        self.guid2name = {}
        with open(filename, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for guid, name in reader:
                self.guid2name[UUID(guid)] = name

    @functools.cached_property
    def name2guid(self):
        """
        Reverse lookup.
        """
        return {name:guid for guid, name in self.guid2name.items()}

    @functools.cached_property
    def legacy_guids(self):
        legacy_guids = {}
        for name, guid in self.name2guid.items():
            if "2Protocol" in name:
                old_name = name.replace("2Protocol", "Protocol")
                if old_name in self.name2guid:
                    legacy_guids[self.name2guid[old_name]] = old_name
        return legacy_guids
        