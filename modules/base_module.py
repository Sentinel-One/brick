import os
import pathlib
import logging
import traceback
from abc import ABC, abstractmethod
import sys
import idc


class BaseModule(ABC):

    def __init__(self) -> None:
        # Initialize logger.
        self.logger = logging.getLogger('brick')
        
        stream_handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(stream_handler)

        input_file_path = pathlib.Path(idc.get_input_file_path())
        log_file_path = input_file_path.with_suffix('.brick')

        file_handler = logging.FileHandler(filename=log_file_path, mode='a+', delay=True)
        file_handler.setFormatter(logging.Formatter('%(levelname)s (%(filename)s): %(message)s'))
        self.logger.addHandler(file_handler)

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

    def close(self):
        logging.shutdown()

        # It is counter intuitive, but the IDA batch mode will pop the UI after executing the script by
        # default, so this allows us to cleanly exit IDA and avoid the UI to pop-up upon completion
        if "DO_EXIT" in os.environ:
            idc.qexit(1)