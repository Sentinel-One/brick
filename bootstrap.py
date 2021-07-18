
from contextlib import contextmanager
import idaapi
idaapi.require('modules.base_module')
idaapi.require('modules.setvar_infoleak.setvar_infoleak')
idaapi.require('modules.setvar_infoleak')
idaapi.require('modules')
idaapi.require('brick_utils')

from modules import AVAILABLE_MODULE_NAMES, MODULE_CLASSES
import idc
import ida_kernwin
import pathlib
import os
import logging

def prompt_interactive_for_module_name():
    while True:
        mod_name = ida_kernwin.ask_text(0, None, 'Enter module name, one of {}'.format(AVAILABLE_MODULE_NAMES))
        if mod_name in AVAILABLE_MODULE_NAMES:
            break
    return [mod_name]

def addLoggingLevel(levelName, levelNum, methodName=None):
    """
    Comprehensively adds a new logging level to the `logging` module and the
    currently configured logging class.

    `levelName` becomes an attribute of the `logging` module with the value
    `levelNum`. `methodName` becomes a convenience method for both `logging`
    itself and the class returned by `logging.getLoggerClass()` (usually just
    `logging.Logger`). If `methodName` is not specified, `levelName.lower()` is
    used.

    To avoid accidental clobberings of existing attributes, this method will
    raise an `AttributeError` if the level name is already an attribute of the
    `logging` module or if the method name is already present 

    Example
    -------
    >>> addLoggingLevel('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5

    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
       raise AttributeError('{} already defined in logging module'.format(levelName))
    if hasattr(logging, methodName):
       raise AttributeError('{} already defined in logging module'.format(methodName))
    if hasattr(logging.getLoggerClass(), methodName):
       raise AttributeError('{} already defined in logger class'.format(methodName))

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)
    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)

@contextmanager
def setup_brick_logger():
    try:
        brick_logger = logging.getLogger('brick')
        input_file_path = pathlib.Path(idc.get_input_file_path())
        log_file_path = input_file_path.with_suffix('.brick')

        file_handler = logging.FileHandler(filename=log_file_path, mode='a+', delay=True)
        file_handler.setFormatter(logging.Formatter('%(levelname)s (%(filename)s): %(message)s'))
        brick_logger.addHandler(file_handler)
        brick_logger.setLevel(logging.DEBUG)

        yield brick_logger
    finally:
        brick_logger.handlers.clear()
    

if __name__ == '__main__':
    if len(idc.ARGV) < 2:
        try:
            modules = open(pathlib.Path(__file__).parent / '.autorun.txt', 'r').read().splitlines()
        except FileNotFoundError:
            modules = prompt_interactive_for_module_name()
    else:
        modules = idc.ARGV[1:]

    try:
        addLoggingLevel('SUCCESS', logging.INFO - 1)
    except AttributeError:
        pass

    with setup_brick_logger():
        for module in modules:
            mod_cls = MODULE_CLASSES[module]
            mod_obj = mod_cls()
            mod_obj.execute()

    # It is counter intuitive, but the IDA batch mode will pop the UI after executing the script by
    # default, so this allows us to cleanly exit IDA and avoid the UI to pop-up upon completion
    if "DO_EXIT" in os.environ:
        idc.qexit(1)
