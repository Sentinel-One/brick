import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_CommBuffer_not_used(session_dir):
    scan_file(f'{session_dir}/PchSmiDispatcher.efi', 'smi_nested_pointers')
    assert text_in_file('SUCCESS (smi_nested_pointers.py)', f'{session_dir}/PchSmiDispatcher.brick')

def test_CommBuffer_does_not_contain_pointers(session_dir):
    scan_file(f'{session_dir}/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.efi', 'smi_nested_pointers')
    assert text_in_file('SUCCESS (smi_nested_pointers.py)', f'{session_dir}/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.brick')

def test_CommBuffer_pointers_validated(session_dir):
    scan_file(f'{session_dir}/0155.efi', 'smi_nested_pointers')
    assert text_in_file('SUCCESS (smi_nested_pointers.py)', f'{session_dir}/0155.brick')

def test_CommBuffer_pointers_not_validated(session_dir):
    scan_file(f'{session_dir}/SpiSmmStub.efi', 'smi_nested_pointers')
    assert text_in_file('ERROR (smi_nested_pointers.py)', f'{session_dir}/SpiSmmStub.brick')
