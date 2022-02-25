//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2016, American Megatrends, Inc.         **
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
  Header file that defines the AmiSmmBufferValidation protocol.
**/
#ifndef __AMI_SMM_BUFFER_VALIDATION_PROTOCOL__H__
#define __AMI_SMM_BUFFER_VALIDATION_PROTOCOL__H__

#define AMI_SMM_BUFFER_VALIDATION_PROTOCOL_GUID \
	{ 0xda473d7f, 0x4b31, 0x4d63, { 0x92, 0xb7, 0x3d, 0x90, 0x5e, 0xf8, 0x4b, 0x84 } }

/**
    Validates memory buffer.
    
    The function verifies the buffer to make sure its address range is legal for a memory buffer.
    SMI handlers that receive buffer address and/or size from outside of SMM at runtime must validate
    the buffer using this function prior to using it or passing to other SMM interfaces.

    @param  Buffer Buffer address 
    @param  BufferSize Size of the Buffer
    
    @retval  EFI_SUCCESS - The buffer address range is valid and can be safely used.
    @retval  EFI_ACCESS_DENIED - The buffer can't be used because its address range overlaps with protected area such as SMRAM.
    @retval  EFI_INVALID_PARAMETER - The buffer can't be used because its address range is invalid.
    @retval  EFI_NOT_FOUND - The buffer can't be used because its validity cannot be verified.
**/
typedef EFI_STATUS (EFIAPI *AMI_SMM_VALIDATE_MEMORY_BUFFER)(CONST VOID* Buffer, CONST UINTN BufferSize);

/**
    Validates MMIO buffer.
    
    The function verifies the buffer to make sure its address range is legal for a MMIO buffer.
    SMI handlers that receive buffer address and/or size from outside of SMM at runtime must validate
    the buffer using this function prior to using it or passing to other SMM interfaces.

    @param  Buffer Buffer address 
    @param  BufferSize Size of the Buffer
    
    @retval  EFI_SUCCESS - The buffer address range is valid and can be safely used.
    @retval  EFI_ACCESS_DENIED - The buffer can't be used because its address range overlaps with protected area such as SMRAM.
    @retval  EFI_INVALID_PARAMETER - The buffer can't be used because its address range is invalid.
    @retval  EFI_NOT_FOUND - The buffer can't be used because its validity cannot be verified.
**/
typedef EFI_STATUS (EFIAPI *AMI_SMM_VALIDATE_MMIO_BUFFER)(CONST VOID* Buffer, CONST UINTN BufferSize);

/**
    Validates SMRAM buffer.
    
    The function verifies the buffer to make sure it resides in the SMRAM.
    
    @param  Buffer Buffer address 
    @param  BufferSize Size of the Buffer
    
    @retval  EFI_SUCCESS - The buffer resides in the SMRAM and can be safely used.
    @retval  EFI_ACCESS_DENIED - The buffer can't be used because at least one byte of the buffer is outside of SMRAM.
    @retval  EFI_INVALID_PARAMETER - The buffer can't be used because its address range is invalid.
    @retval  EFI_NOT_FOUND - The buffer can't be used because its validity cannot be verified.
**/
typedef EFI_STATUS (EFIAPI *AMI_SMM_VALIDATE_SMRAM_BUFFER)(CONST VOID* Buffer, CONST UINTN BufferSize);

/** AMI SMM Buffer Validation Protocol.
  The protocol functions are used to validate buffers that are used for SMM communication.
**/
typedef struct  {
    AMI_SMM_VALIDATE_MEMORY_BUFFER ValidateMemoryBuffer;
    AMI_SMM_VALIDATE_MMIO_BUFFER ValidateMmioBuffer;
    AMI_SMM_VALIDATE_SMRAM_BUFFER ValidateSmramBuffer;
} AMI_SMM_BUFFER_VALIDATION_PROTOCOL;

extern EFI_GUID gAmiSmmBufferValidationProtocolGuid;

#endif
//**********************************************************************
//**********************************************************************
//**                                                                  **
//**        (C)Copyright 1985-2016, American Megatrends, Inc.         **
//**                                                                  **
//**                       All Rights Reserved.                       **
//**                                                                  **
//**      5555 Oakbrook Parkway, Suite 200, Norcross, GA 30093        **
//**                                                                  **
//**                       Phone: (770)-246-8600                      **
//**                                                                  **
//**********************************************************************
//**********************************************************************