import logging
import traceback
from abc import ABC, abstractmethod
import sys

class BaseModule(ABC):

    def __init__(self) -> None:
        self.logger = logging.getLogger('brick')

    @abstractmethod
    def run(self):
        pass

    def execute(self):
        try:
            self.run()
        except Exception as e:
            self.logger.error(e)
            tb = sys.exc_info()[2]
            self.logger.error(traceback.format_tb(tb))
