from contextlib import contextmanager
import logging
from abc import ABC, abstractmethod, abstractproperty
import idaapi

class BaseModule(ABC):

    def __init__(self, is_interactive=False) -> None:
        self.logger = logging.getLogger('brick')
        self.res = True
        self.is_interactive = is_interactive
        self.input_file = idaapi.get_input_file_path()
        self.is_64bit = idaapi.get_inf_structure().is_64bit()

    @abstractmethod
    def run(self):
        # Should be overriden by subclasses.
        pass
