import logging
import traceback
from abc import ABC, abstractmethod
import sys
import ida_kernwin

class BaseModule(ABC):

    def __init__(self, is_interactive=False) -> None:
        self.logger = logging.getLogger('brick')
        self.res = True
        self.is_interactive = is_interactive

    @abstractmethod
    def run(self):
        # Should be overriden by subclasses.
        pass
