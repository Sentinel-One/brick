from ..factory.factory import UefiCallFactory

from .GetVariable import GetVariableCall
from .SetVariable import SetVariableCall

EfiRuntimeServices = UefiCallFactory()
EfiRuntimeServices.register('GetVariable',    GetVariableCall)
EfiRuntimeServices.register('SetVariable',    SetVariableCall)