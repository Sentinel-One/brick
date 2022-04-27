//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2015, American Megatrends, Inc.         **
//**                                                                  **
//**                       All Rights Reserved.                       **
//**                                                                  **
//**      5555 Oakbrook Parkway, Suite 200, Norcross, GA 30093        **
//**                                                                  **
//**                       Phone: (770)-246-8600                      **
//**                                                                  **
//**********************************************************************
//**********************************************************************
/** @file
  Header file that defines the AmiNvramUpdate protocol interfaces.
**/
#ifndef __AMI_NVRAM_UPDATE_PROTOCOL__H__
#define __AMI_NVRAM_UPDATE_PROTOCOL__H__

#define AMI_NVRAM_UPDATE_PROTOCOL_GUID \
	{ 0xdde31574, 0x3589, 0x4fa9, { 0xbc, 0x69, 0x17, 0x29, 0xaf, 0x6f, 0xda, 0x4e } }

#define AMI_SMM_NVRAM_UPDATE_PROTOCOL_GUID \
	{ 0xf3224a5e, 0x17a3, 0x47c2, { 0xa3, 0x8b, 0x48, 0x14, 0x56, 0x86, 0x3c, 0x74 } }

typedef struct _AMI_NVRAM_UPDATE_PROTOCOL AMI_NVRAM_UPDATE_PROTOCOL;

/**
  The function is used during firmware update to replace current NVRAM content with the new content
  extracted from the firmware image being flashed.
  
  @param This				Pointer to the protocol instance
  @param NvramBuffer		Address of the new NVRAM image
  @param NvramBufferSize	Size of the new NVRAM image
  @param UpdateNvram		When UpdateNvram is TRUE, the function will proceed with the NVRAM update.
                            This is preferred NVRAM update mode.
                            When UpdateNvram is FALSE, the function will not modify NVRAM content. 
                            It will instead modify content of the NvramBuffer to add variables that are to be preserved across firmware updates.
                            The caller is responsible for flashing of the updated NVRAM image.
                            UpdateNvram should be set to TRUE unless NVRAM size or location within flash device has changed.
                            When UpdateNvram is TRUE, NVRAM is updated in a fault tolerant manner.
                            When UpdateNvram is FALSE, fault tolerance is a caller responsibility.
  
  @retval EFI_INVALID_PARAMETER NvramBuffer or NvramBufferSize is NULL
  @retval EFI_BAD_BUFFER_SIZE UpdateNvram is TRUE and NvramBufferSize is different than the current NVRAM size
  @retval EFI_VOLUME_CORRUPTED NvramBuffer content does not constitute a valid NVRAM image
  @retval EFI_DEVICE_ERROR NVRAM update has failed due to a device error
  @retval EFI_SUCCESS The operation completed successfully.
**/
typedef EFI_STATUS (EFIAPI *AMI_NVRAM_UPDATE_NVRAM)(
	AMI_NVRAM_UPDATE_PROTOCOL *This,
	VOID *NvramBuffer, UINTN NvramBufferSize, BOOLEAN UpdateNvram
);

/**
  The function is used after firmware update to bind NVRAM driver to a new NVRAM location.
  
  The function is used after firmware update to notify NVRAM driver about new 
  location of the NVRAM areas in the flash device.

  NOTE: UpdateNvram function should be used when possible.
        This function should only be used if UpdateNvram function cannot be used due to implementation constrains.

  @param This               Pointer to the protocol instance
  @param NvramAddress       Address of the NVRAM area in the updated firmware image 
                            (the image that has just been flashed).
  @param NvramAddress       Address of the NVRAM backup area in the updated firmware image 
                            (the image that has just been flashed). 
                            The value should be set to 0 if back area is not supported.
  @param NvramSize          Size of the new NVRAM image
  
  @retval EFI_INVALID_PARAMETER invalid NVRAM address or size
  @retval EFI_DEVICE_ERROR Operation has failed due to a device error
  @retval EFI_SUCCESS The operation completed successfully.
**/
typedef EFI_STATUS (EFIAPI *AMI_NVRAM_MIGRATE_NVRAM)(
    AMI_NVRAM_UPDATE_PROTOCOL *This,
    UINT64 NvramAddress, UINT64 NvramBackupAddress, UINTN NvramSize
);

/** AMI NVRAM Update Protocol.
  The protocol functions are used to notify NVRAM driver about firmware update which involves update of the NVRAM flash areas.
  
  UpdateNvram and MigrateNvram provide two alternative methods to handle firmware updates.
**/
struct _AMI_NVRAM_UPDATE_PROTOCOL {
    AMI_NVRAM_UPDATE_NVRAM UpdateNvram;
    AMI_NVRAM_MIGRATE_NVRAM MigrateNvram;
};

extern EFI_GUID gAmiNvramUpdateProtocolGuid;
extern EFI_GUID gAmiSmmNvramUpdateProtocolGuid;

#endif
//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2015, American Megatrends, Inc.         **
//**                                                                  **
//**                       All Rights Reserved.                       **
//**                                                                  **
//**      5555 Oakbrook Parkway, Suite 200, Norcross, GA 30093        **
//**                                                                  **
//**                       Phone: (770)-246-8600                      **
//**                                                                  **
//**********************************************************************
//**********************************************************************
