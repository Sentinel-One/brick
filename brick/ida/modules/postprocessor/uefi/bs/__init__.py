from ..factory.factory import UefiCallFactory

from .LocateProtocol import LocateProtocolCall

EfiBootServices = UefiCallFactory()
EfiBootServices.register('LocateProtocol',    LocateProtocolCall)