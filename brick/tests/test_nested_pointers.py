import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_CommBuffer_not_used():
    scan_file('bin/PchSmiDispatcher.efi', 'smm_buffer')
    assert text_in_file('SUCCESS (check_nested_pointers.py)', 'bin/PchSmiDispatcher.brick')

def test_CommBuffer_does_not_contain_pointers():
    scan_file('bin/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.efi', 'smram_overlap')
    assert text_in_file('ERROR (smram_overlap.py)', 'bin/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.brick')

def test_CommBuffer_pointers_validated():
    scan_file('bin/0155.efi', 'smram_overlap')
    assert text_in_file('SUCCESS (smram_overlap.py)', 'bin/0155.brick')

def test_CommBuffer_pointers_not_validated():
    scan_file('bin/SpiSmmStub.efi', 'smm_buffer')
    assert text_in_file('ERROR (check_nested_pointers.py)', 'bin/SpiSmmStub.brick')
