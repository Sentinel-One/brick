from ...factory.factory import UefiCallFactory

from .GetCapabilities import GetCapabilitiesCall

SmmAccess2Protocol = UefiCallFactory()
SmmAccess2Protocol.register('GetCapabilities',    GetCapabilitiesCall)