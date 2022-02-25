import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_CommBuffer_not_referenced(session_dir):
    scan_file(f'{session_dir}/PchSmiDispatcher.efi', 'low_smram_corruption')
    assert text_in_file('SUCCESS (low_smram_corruption.py)', f'{session_dir}/PchSmiDispatcher.brick')

def test_vulnerable(session_dir):
    scan_file(f'{session_dir}/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.efi', 'low_smram_corruption')
    assert text_in_file('ERROR (low_smram_corruption.py)', f'{session_dir}/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.brick')

def test_CommBufferSize_dereferenced(session_dir):
    scan_file(f'{session_dir}/0155.efi', 'low_smram_corruption')
    assert text_in_file('SUCCESS (low_smram_corruption.py)', f'{session_dir}/0155.brick')

def test_CommBuffer_verified(session_dir):
    pass
