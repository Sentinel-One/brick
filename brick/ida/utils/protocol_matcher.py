from bip.base import *
from bip.hexrays import *

from . import brick_utils
import uuid

from collections import namedtuple

class ProtocolMatcher:

    Result = namedtuple('ProtocolRecognizerResult', ['Guid', 'Instances'])

    def __init__(self, guid, name, is_smm=False):

        if not isinstance(guid, uuid.UUID):
            guid = uuid.UUID(guid)

        self.guid = guid
        self.name = name
        self.is_smm = is_smm

    def match(self):

        def rename_protocol_instances(cn: CNodeExprCall):
            if self.is_smm:
                service_name = '->SmmLocateProtocol'
            else:
                service_name = '->LocateProtocol'

            if service_name in cn.cstr:
                if self.name in cn.get_arg(0).cstr:
                    interface = cn.get_arg(2).ignore_cast
                    if isinstance(interface, CNodeExprRef):
                        # if we have a ref (&global) we want the object under
                        interface = interface.ops[0].ignore_cast
                    if not isinstance(interface, CNodeExprObj):
                        # if this is not a global object we ignore it
                        return
                    ea = interface.value # get the address of the object
                    BipElt(ea).name = f'g_{self.name}_{ea}'

        found = brick_utils.search_guid(self.guid)
        if found:
            elt = BipElt(found.ea)
            elt.name = self.name

            # Rename instances.
            for hxcfunc in HxCFunc.iter_all():
                try:
                    hxcfunc.visit_cnode_filterlist(rename_protocol_instances, [CNodeExprCall])
                except Exception as e:
                    self.logger.debug(e)

    def get(self):
        return ProtocolMatcher.Result(GetEltByName(self.name), BipElt.get_by_prefix(f'g_{self.name}'))
