from ...factory.factory import UefiCallFactory

from .ReadSaveState import ReadSaveStateCall
from .WriteSaveState import WriteSaveStateCall

SmmCpuCallsFactory = UefiCallFactory()
SmmCpuCallsFactory.register('ReadSaveState',    ReadSaveStateCall)
SmmCpuCallsFactory.register('WriteSaveState',   WriteSaveStateCall)