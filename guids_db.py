import csv
import functools

class GuidsDatabase:

    def __init__(self, filename):
        self.guid2name = {}
        with open(filename, 'r') as csvfile:
            reader = csv.reader(csvfile)
            for guid, name in reader:
                self.guid2name[guid.lower()] = name

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
        