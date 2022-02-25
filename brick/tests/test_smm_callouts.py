import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_FreePool_false_callout(session_dir):
    print('Session dir ', session_dir)
    scan_file(f'{session_dir}/000C.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', f'{session_dir}/000C.brick')

def test_SmmRuntimeService_false_callout(session_dir):
    scan_file(f'{session_dir}/SmiFlash.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', f'{session_dir}/SmiFlash.brick')

def test_true_callout(session_dir):
    scan_file(f'{session_dir}/0511.efi', 'callouts')
    assert text_in_file('ERROR (callouts.py)', f'{session_dir}/0511.brick')
    
def test_no_callouts(session_dir):
    scan_file(f'{session_dir}/WwanSmm.efi', 'callouts')
    assert text_in_file('SUCCESS (callouts.py)', f'{session_dir}/WwanSmm.brick')
    