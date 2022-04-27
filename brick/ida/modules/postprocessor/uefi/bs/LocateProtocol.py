from ..base import CNodeExprIndirectCall
from brick.ida.modules.efiXplorer.efiXplorer import EfiXplorerPlugin

from bip.base import *
from bip.hexrays import *

import typing
import logging

class LocateProtocolCall(CNodeExprIndirectCall):
    """Represents a call to LocateProtocol()"""

    PROTOTYPE = 'EFI_LOCATE_PROTOCOL'

    @property
    def Protocol(self):
        return self.get_arg(0)

    @property
    def protocol_var(self):
        '''Returns the variable for the Protocol as either CNodeExprVar or CNodeExprObj'''

        protocol = self.Protocol.ignore_cast
        if not isinstance(protocol, CNodeExprRef):
            # Unexpected.
            raise TypeError(f'Protocol argument is expected to be a reference node, got {protocol} instead')

        protocol = protocol.operand
        if not isinstance(protocol, (CNodeExprVar, CNodeExprObj)):
            # Unexpected.
            raise TypeError(f'Protocol variable is expected to be either a local or global variable, got {protocol} instead')

        return protocol

    @property
    def protocol_name(self):
        '''Returns the frienly name of the Protocol'''

        protocol_var = self.protocol_var
        if isinstance(protocol_var, CNodeExprVar):
            # Interface is a local variable.
            return protocol_var.lvar_name
        elif isinstance(protocol_var, CNodeExprObj):
            # Protocol is a global variable.
            return protocol_var.value_as_elt.name
        else:
            # Unexpected.
            raise TypeError(f'Protocol argument is expected to be either a local or global variable, got {protocol_var} instead')

    def is_known_protocol(self):
        '''Returns whether or not the Protocol has a known GUID (i.e. recognized by efiXplorer)'''

        protocol_var = self.protocol_var
        if isinstance(protocol_var, CNodeExprVar):
            # Protocol is a local variable. This is currently unsupported by us.
            # TODO: Reconstruct the GUID of the protocol using emulation.
            return False
        elif isinstance(protocol_var, CNodeExprObj):
            # Protocol is a global variable.
            protocol_guid = protocol_var.value_as_elt
            return     protocol_guid.is_user_name and \
                   not protocol_guid.name.startswith(EfiXplorerPlugin.ROPRIETARY_PROTOCOL_PREFIX)
        else:
            # Unexpected.
            raise TypeError(f'Protocol variable is expected to be either a local or global variable, got {protocol_var} instead')

    @property
    def Registration(self):
        return self.get_arg(1)

    @property
    def Interface(self):
        return self.get_arg(2)

    @property
    def interface_var(self) -> typing.Union[CNodeExprVar, CNodeExprObj]:
        '''Returns the variable for the Interface as either CNodeExprVar or CNodeExprObj'''

        interface = self.Interface.ignore_cast
        if not isinstance(interface, CNodeExprRef):
            # Unexpected.
            raise TypeError(f'Interface argument is expected to be a reference node, got {interface} instead')

        interface = interface.operand
        if not isinstance(interface, (CNodeExprVar, CNodeExprObj)):
            # Unexpected.
            raise TypeError(f'Interface variable is expected to be either a local or global variable, got {interface} instead')

        return interface

    def is_known_interface(self):
        interface_var = self.interface_var
        if isinstance(interface_var, CNodeExprVar):
            # Interface is a local variable.
            return interface_var.lvar.has_user_name
        elif isinstance(interface_var, CNodeExprObj):
            # Protocol is a global variable.
            return interface_var.value_as_elt.is_user_name
        else:
            # Unexpected.
            raise TypeError(f'Interface argument is expected to be either a local or global variable, got {interface_var} instead')

    def process(self):
        # Recent version of efiXplorer already take care of assigning the correct type to the
        # interface pointer.
        try:
            if self.is_known_protocol() and not self.is_known_interface():
                logging.getLogger('brick').debug(f'Interface definition for protocol {self.protocol_name} is missing')
        except TypeError as e:
            logging.getLogger('brick').debug(e)
