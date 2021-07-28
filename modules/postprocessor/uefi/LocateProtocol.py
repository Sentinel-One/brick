from ..base import UefiCall, set_cnode_name, set_cnode_type
from bip.base import *
from bip.hexrays import *

class LocateProtocolCall(UefiCall):
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
        if not isinstance(protocol, CNodeExprObj):
            return

        # Get a friendly name for the protocol.
        # For example, use just EFI_SMM_VARIABLE_PROTOCOL instead of EFI_SMM_VARIABLE_PROTOCOL_GUID_8A40.
        protocol_name = BipElt(protocol.value).name
        protocol_name = protocol_name[:protocol_name.find('_GUID_')]

        interface = self.Interface.ignore_cast

        # Rename the interface pointer to match the protocol's name.
        set_cnode_name(interface, protocol_name)

        try:
            interface_pointer_type = BipType.from_c(f'{protocol_name} *')
        except RuntimeError:
            # The pointer type is not recognized, set to PVOID.
            interface_pointer_type = BipType.from_c('void *')

        set_cnode_type(interface, interface_pointer_type)

