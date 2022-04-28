from ...bs.LocateProtocol import LocateProtocolCall
from ...factory.factory import UefiCallFactory

from .SmiHandlerRegister import SmiHandlerRegisterCall, SmiHandlerUnRegisterCall

SmstFactory = UefiCallFactory()
SmstFactory.register('SmiHandlerRegister',  SmiHandlerRegisterCall)
SmstFactory.register('SmiHandlerUnRegister',  SmiHandlerUnRegisterCall)
SmstFactory.register('SmmLocateProtocol',   LocateProtocolCall)
