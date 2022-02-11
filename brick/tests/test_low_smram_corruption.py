import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_CommBuffer_not_referenced():
    scan_file('bin/PchSmiDispatcher.efi')
    assert text_in_file('SUCCESS (smram_overlap.py)', 'bin/PchSmiDispatcher.brick')

def test_vulnerable():
    scan_file('bin/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.efi')
    assert text_in_file('ERROR (smram_overlap.py)', 'bin/619C2B94-FE5A-45C3-B445-C6AF9BDD7CE0.brick')

def test_CommBufferSize_dereferenced():
    scan_file('bin/0155.efi')
    assert text_in_file('SUCCESS (smram_overlap.py)', 'bin/0155.brick')
