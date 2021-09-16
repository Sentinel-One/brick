BRICK_FULL_RUN_MODULES = (
    'preprocessor',
    'efiXplorer',
    'postprocessor',
    'smm_buffer',
    'toctou',
    'legacy_protocols',
    'is_edk2',
    'cseg',
    'setvar_infoleak',
)

# A subset of all modules.
BRICK_QUICK_RUN_MODULES = (
    'preprocessor',
    'efiXplorer',
    'postprocessor',
    'smm_buffer',
    'toctou',
    'setvar_infoleak',
)

BRICK_MODULES_DESCRIPTIONS = {
    'preprocessor': 'Pre-processing',
    'efiXplorer': 'Analyzing a SMM binary with efiXplorer',
    'postprocessor': 'Post-processing',
    'smm_buffer': 'Scanning for SMI handlers not calling SmmIsBufferOutsideSmmValid() or equivalent on the CommBuffer',
    'toctou': 'Scanning for SMI handlers that are subject to a TOCTOU attack',
    'legacy_protocols': 'Scanning for SMM modules which use legacy or deprecated protocols',
    'is_edk2': 'Checking whether or not the SMM binary comes from a reference implementation such as EDK2',
    'cseg': 'Scanning for SMI handlers which only protect the CSEG region',
    'setvar_infoleak': 'Scanning for calls to SetVariable() which might leak out SMRAM data',
}

try:
    import idaapi
    # Imported in the context of IDA.
    in_ida = True
except ImportError:
    # Not imported in the context of IDA.
    in_ida = False

if in_ida:
    from .preprocessor.preprocessor import PreprocessorModule
    from .efiXplorer.efiXplorer_module import EfiXplorerModule
    from .postprocessor.postprocessor import PostprocessorModule
    from .cseg.scan_cseg import CsegOnlyModule
    from .legacy_protocols.legacy_protocols import LegacyProtocolsModule
    from .reference_code.is_edk2 import IsEdk2Module
    from .buffer_outside_smm.check_buffer_outside_smm import SmmBufferValidModule
    from .toctou.toctou import ToctouModule
    from .setvar_infoleak.setvar_infoleak import SetVarInfoLeakModule

    BRICK_MODULES_CLASSES = {
        'preprocessor': PreprocessorModule,
        'efiXplorer': EfiXplorerModule,
        'postprocessor': PostprocessorModule,
        'smm_buffer': SmmBufferValidModule,
        'toctou': ToctouModule,
        'legacy_protocols': LegacyProtocolsModule,
        'is_edk2': IsEdk2Module,
        'cseg': CsegOnlyModule,
        'setvar_infoleak': SetVarInfoLeakModule,
}
