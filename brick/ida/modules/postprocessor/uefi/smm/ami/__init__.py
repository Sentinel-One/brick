
from ...factory.factory import UefiCallFactory

from .AmiSmmBufferValidation import ValidateMemoryBufferCall, ValidateMmioBufferCall, ValidateSmramBufferCall

AmiSmmBufferValidationFactory = UefiCallFactory()
AmiSmmBufferValidationFactory.register('ValidateMemoryBuffer',  ValidateMemoryBufferCall)
AmiSmmBufferValidationFactory.register('ValidateMmioBuffer',   ValidateMmioBufferCall)
AmiSmmBufferValidationFactory.register('ValidateSmramBuffer',   ValidateSmramBufferCall)
