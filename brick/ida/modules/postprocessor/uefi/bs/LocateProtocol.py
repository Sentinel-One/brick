from ..base import CNodeExprIndirectCall, set_cnode_name, set_cnode_type

from bip.base import *
from bip.hexrays import *
import re


def camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


class LocateProtocolCall(CNodeExprIndirectCall):
    """Represents a call to LocateProtocol()"""

    PROTOTYPE = 'EFI_LOCATE_PROTOCOL'

    @property
    def Protocol(self):
        return self.get_arg(0)

    @property
    def Registration(self):
        return self.get_arg(1)

    @property
    def Interface(self):
        return self.get_arg(2)

    def process(self):
        # Get the protocol argument.
        protocol = self.Protocol.ignore_cast
        if isinstance(protocol, CNodeExprRef):
            protocol = protocol.ops[0].ignore_cast

        # We expect the protocol GUID to be a global variable.
        if isinstance(protocol, CNodeExprObj):
            protocol_name = BipElt(protocol.value).name
        elif isinstance(protocol, CNodeExprVar):
            protocol_name = protocol.lvar.name
        else:
            return

        # Get a friendly name for the protocol.
        # For example, use just EFI_SMM_VARIABLE_PROTOCOL instead of EFI_SMM_VARIABLE_PROTOCOL_GUID_8A40.
        if (idx := (protocol_name.find('_GUID_'))) != -1:
            interface_name = protocol_name[:idx]
        elif protocol_name.startswith('gEfi') and (idx := protocol_name.find('Guid_')) != -1:
            interface_name = camel_to_snake(protocol_name[1:idx]).upper()
            print(f'Interface name is {interface_name}')
        else:
            interface_name = protocol_name

        interface = self.Interface.ignore_cast

        # Rename the interface pointer to match the protocol's name.
        set_cnode_name(interface, interface_name)

        try:
            interface_pointer_type = BipType.from_c(f'{interface_name} *')
        except RuntimeError:
            # The pointer type is not recognized, set to PVOID.
            interface_pointer_type = BipType.from_c('void *')

        set_cnode_type(interface, interface_pointer_type)

