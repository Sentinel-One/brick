import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_FreePool_false_callout():
    scan_file('bin/000C.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', 'bin/000C.brick')

def test_SmmRuntimeService_false_callout():
    scan_file('bin/SmiFlash.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', 'bin/SmiFlash.brick')

def test_true_callout():
    scan_file('bin/0511.efi', 'callouts')
    assert text_in_file('ERROR (callouts.py)', 'bin/0511.brick')
    
def test_no_callouts():
    scan_file('bin/WwanSmm.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', 'bin/WwanSmm.brick')
    