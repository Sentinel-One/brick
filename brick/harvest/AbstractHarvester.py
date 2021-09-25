from abc import ABC, abstractmethod
from signal import valid_signals
import shutil
from pathlib import Path
from logger import log_operation
class AbstractHarvester(ABC):

    def __init__(self):
        self._guids_dict = {}
        self._ext = None
        self.filter = lambda *args: True

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
    def iter(self, rom):
        pass

    def harvest(self, rom, outdir):
        for (name, fd) in self.iter(rom):
            
            if not self.filter(name, fd):
                log_operation(f'Skipping {name}')
                continue

            dest = (Path(outdir) / name).with_suffix(f'.{self.ext}')
            with open(dest, 'wb') as dest_fd:
                log_operation(f'Dumping {dest} to disk')
                # import os
                
                shutil.copyfileobj(fd, dest_fd)
