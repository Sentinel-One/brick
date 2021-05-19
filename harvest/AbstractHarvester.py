from abc import ABC, abstractmethod

class AbstractHarvester(ABC):

    def __init__(self):
        self._guids_dict = {}
        self._ext = None

    @property
    def guids_dict(self):
        return self._guids_dict

    @guids_dict.setter
    def guids_dict(self, guids):
        self._guids_dict = guids

    @property
    def ext(self):
        return self._ext

    @ext.setter
    def ext(self, value):
        self._ext = value

    def guid2name(self, guid):
        guid = guid.lower()
        try:
            return self.guids_dict[guid]
        except KeyError:
            return guid

    @abstractmethod
    def harvest(self, rom, outdir):
        pass
