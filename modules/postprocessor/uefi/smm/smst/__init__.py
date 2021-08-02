from ...factory.factory import UefiCallFactory

from .SmiHandlerRegister import SmiHandlerRegisterCall

SmstFactory = UefiCallFactory()
SmstFactory.register('SmiHandlerRegister',    SmiHandlerRegisterCall)