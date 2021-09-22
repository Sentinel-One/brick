from edk2toollib.uefi.edk2.guid_list import GuidList

from externals import get_external

EDK2_DIR = str(get_external('edk2'))
EDK2_PLATFORMS = str(get_external('edk2-platforms'))

edk2_names = [n.name.lower() for n in GuidList.guidlist_from_filesystem(EDK2_DIR) + \
                                      GuidList.guidlist_from_filesystem(EDK2_PLATFORMS)]

edk2_guids = [g.guid.lower() for g in GuidList.guidlist_from_filesystem(EDK2_DIR) + \
                                      GuidList.guidlist_from_filesystem(EDK2_PLATFORMS)]

def skip_edk2_filter(name, fd):
    return name.lower() in edk2_names or name.lower() is edk2_guids
