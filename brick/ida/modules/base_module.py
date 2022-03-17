import os
import logging
from abc import ABC, abstractmethod
import idaapi
from ..utils.watchdog import Watchdog

class BaseModule(ABC):

    def __init__(self, is_interactive=False) -> None:
        self.logger = logging.getLogger('brick')
        self.res = True
        self.is_interactive = is_interactive
        self.input_file = idaapi.get_input_file_path()
        self.is_64bit = idaapi.get_inf_structure().is_64bit()

    DEPENDS_ON = []

    @abstractmethod
    def run(self):
        # Should be overriden by subclasses.
        pass

    def timed_run(self, timeout):
        def self_terminate():
            self.logger.fatal(f'Timeout executing module {self.__class__.__name__}')
            # Forcefully kill the process.
            os.kill(os.getpid(), 0)

        with Watchdog(timeout, self_terminate):
            self.run()

