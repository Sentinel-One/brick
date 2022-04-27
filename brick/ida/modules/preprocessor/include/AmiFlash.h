//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2014, American Megatrends, Inc.         **
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
  Header file that defines the Flash protocol interfaces.
**/
#ifndef __AMI_FLASH_PROTOCOL__H__
#define __AMI_FLASH_PROTOCOL__H__

#define AMI_FLASH_PROTOCOL_GUID \
    { 0x755b6596, 0x6896, 0x4ba3, { 0xb3, 0xdd, 0x1c, 0x62, 0x9f, 0xd1, 0xea, 0x88 } }

#define AMI_SMM_FLASH_PROTOCOL_GUID \
    { 0xecb867ab, 0x8df4, 0x492d, { 0x81, 0x50, 0xa7, 0xfd, 0x1b, 0x9b, 0x5a, 0x75 } }

typedef struct _AMI_FLASH_PROTOCOL AMI_FLASH_PROTOCOL;

/**
  Read Size number of bytes from the FlashAddress and place them into the DataBuffer.

  @param FlashAddress Physical address in the flash part to start reading
  @param Size Number of bytes to read from the flash part
  @param DataBuffer Buffer to place the data read from the flash part
  
  @return EFI_STATUS
  @retval EFI_SUCCESS
  @retval
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_READ)(
    IN     VOID     *FlashAddress, 
    IN     UINTN    Size, 
    IN OUT VOID     *DataBuffer
);

/**
  Starting at the FlashAddress, erase the requested number of bytes.

  @param FlashAddress Physical address in the flash part to start reading
  @param Size Number of bytes to read from the flash part
  
  @return EFI_STATUS
  @retval EFI_SUCCESS
  @retval
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_ERASE)(
    IN VOID *FlashAddress, 
    IN UINTN Size
);

/**
  Write the requested number of bytes starting at FlashAddress

  @param FlashAddress Physical address in the flash part to start reading
  @param Size Number of bytes to read from the flash part
  @param DataBuffer Buffer with the data to write into the flash part
  
  @return EFI_STATUS
  @retval EFI_SUCCESS
  @retval
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_WRITE)(
    IN  VOID *FlashAddress, 
    IN  UINTN Size, 
    IN  VOID *DataBuffer
);

/**
  Verify that the data at FlashAddress matches the passed DataBuffer. If it
  does not match, then write the data in DataBuffer into area of the Flash.

  @param FlashAddress Physical address in the flash part to start reading
  @param Size Number of bytes to read from the flash part
  @param DataBuffer Buffer with the data to write into the flash part
  
  @return EFI_STATUS
  @retval EFI_SUCCESS
  @retval
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_UPDATE)(
    IN  VOID *FlashAddress, 
    IN  UINTN Size, 
    IN  VOID *DataBuffer
);

/**
  Enable the ability to write to the flash part.
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_WRITE_ENABLE)(VOID);

/**
  Disable the ability to write to the flash part.
**/
typedef EFI_STATUS (EFIAPI *AMI_FLASH_WRITE_DISABLE)(VOID);

struct _AMI_FLASH_PROTOCOL {
    AMI_FLASH_READ              Read;
    AMI_FLASH_ERASE             Erase;
    AMI_FLASH_WRITE             Write;
    AMI_FLASH_UPDATE            Update;
    AMI_FLASH_WRITE_ENABLE      DeviceWriteEnable;
    AMI_FLASH_WRITE_DISABLE     DeviceWriteDisable; 
};

extern EFI_GUID gAmiFlashProtocolGuid;
extern EFI_GUID gAmiSmmFlashProtocolGuid;

#endif
//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2014, American Megatrends, Inc.         **
//**                                                                  **
//**                       All Rights Reserved.                       **
//**                                                                  **
//**      5555 Oakbrook Parkway, Suite 200, Norcross, GA 30093        **
//**                                                                  **
//**                       Phone: (770)-246-8600                      **
//**                                                                  **
//**********************************************************************
//**********************************************************************
