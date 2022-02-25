BRICK_FULL_RUN_MODULES = (
    'preprocessor',
    'efiXplorer',
    'postprocessor',
    'callouts',
    'smi_nested_pointers',
    'low_smram_corruption',
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
    'smi_nested_pointers',
    'toctou',
    'setvar_infoleak',
)

BRICK_MODULES_DESCRIPTIONS = {
    'preprocessor': 'Pre-processing',
    'efiXplorer': 'Analyzing a SMM binary with efiXplorer',
    'postprocessor': 'Post-processing',
    'callouts': 'Detects SMM callouts',
    'smi_nested_pointers': 'Scanning for SMI handlers not calling SmmIsBufferOutsideSmmValid() or equivalent on the CommBuffer',
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
    from .callouts.callouts import EfiXplorerModule
    from .postprocessor.postprocessor import PostprocessorModule
    from .callouts.callouts import SmmCalloutsModule
    from .cseg.scan_cseg import CsegOnlyModule
    from .legacy_protocols.legacy_protocols import LegacyProtocolsModule
    from .reference_code.is_edk2 import IsEdk2Module
    from .smi_nested_pointers.smi_nested_pointers import SmiNestedPointersModule
    from .low_smram_corruption.low_smram_corruption import LowSmramCorruptionModule
    from .toctou.toctou import ToctouModule
    from .setvar_infoleak.setvar_infoleak import SetVarInfoLeakModule

    BRICK_MODULES_CLASSES = {
        'preprocessor': PreprocessorModule,
        'efiXplorer': EfiXplorerModule,
        'postprocessor': PostprocessorModule,
        'callouts': SmmCalloutsModule,
        'smi_nested_pointers': SmiNestedPointersModule,
        'low_smram_corruption': LowSmramCorruptionModule,
        'toctou': ToctouModule,
        'legacy_protocols': LegacyProtocolsModule,
        'is_edk2': IsEdk2Module,
        'cseg': CsegOnlyModule,
        'setvar_infoleak': SetVarInfoLeakModule,
}
