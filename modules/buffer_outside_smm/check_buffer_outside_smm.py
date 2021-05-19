import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parents[1]))
from base_module import BaseModule

import os
import idc

import rizzo
import idautils
import alleycat
from contextlib import closing
import uuid

from bip.base import *
import bip_utils

class SmmBufferValidModule(BaseModule):

    SIGDIR = Path(__file__).parent / r"sig"
    AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID = '{da473d7f-4b31-4d63-92b7-3d905ef84b84}'
    EFI_SMM_CPU_PROTOCOL_GUID = '{EB346B97-975F-4A9F-8B22-F8E92BB3D569}'

    @staticmethod
    def _get_SmmIsBufferOutsideSmmValid(sigdir):
        for sig in os.listdir(sigdir):
            sigfile = os.path.join(sigdir, sig)
            # Apply signature for SmmIsBufferOutsideSmmValid.
            rizzo.RizzoApply(sigfile)

        # Check if we have a match.
        return BipFunction.get_by_name("SmmIsBufferOutsideSmmValid")

    @staticmethod
    def _get_sw_smi_handlers() -> list:
        return BipFunction.get_by_prefix("SwSmiHandler")

    @staticmethod
    def _get_comm_buffer_smi_handlers() -> list:
         return [f for f in BipFunction.get_by_prefix("Handler") if f.size > 10]

    def references_ami_smm_buffer_validation_protocol(self):
        # Some SMM modules use the AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID protocol instead of calling
        # SmmIsBufferOutsideSmmValid directly.
        return bip_utils.search_guid(self.AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID)

    def _run(self):

        # ################# #
        # Main module logic #
        # ################# #

        if self.references_ami_smm_buffer_validation_protocol():
            return

        SmmIsBufferOutsideSmmValid = self._get_SmmIsBufferOutsideSmmValid(self.SIGDIR)

        # Communicate()-based SMIs are always part of the attack surface.
        attack_surface_smis = self._get_comm_buffer_smi_handlers()

        if bip_utils.search_guid(self.EFI_SMM_CPU_PROTOCOL_GUID):
            # This module consumes the EFI_SMM_CPU_PROTOCOL. That means SW SMI handlers can call ReadSaveState() to retrieve arguments to the call.
            # Therefore, we'll add them to the potential attack surface.
            attack_surface_smis.extend(self._get_sw_smi_handlers())
        else:
            # This module doesn't consume the EFI_SMM_CPU_PROTOCOL. That means all the SW SMI handlers don't call ReadSaveState() to retrieve arguments to the call.
            # Therefore, we won't consider them part of the potential attack surface.
            pass

        for handler in attack_surface_smis:
            suspicious = False
            if not SmmIsBufferOutsideSmmValid:
                suspicious = True
            else:
                paths = alleycat.AlleyCat(SmmIsBufferOutsideSmmValid.ea, handler.ea).paths
                if not paths:
                    suspicious = True
                else:
                    # This indicates the handler calls SmmIsBufferOutsideSmmValid on nested pointers in addition to the CommBuffer itself.
                    pass

            if suspicious:
                self.logger.warning(f"SMI at 0x{handler.ea:x} doesn't call SmmIsBufferOutsideSmmValid(), check nested pointers")

with closing(SmmBufferValidModule()) as module:
    module.run()

