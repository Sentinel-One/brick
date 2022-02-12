import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_module_from_edk2():
    scan_file('bin/SmmLockBox.efi', 'is_edk2')
    assert text_in_file('SmmLockBox is from EDK2', 'bin/SmmLockBox.brick')

def test_module_not_from_edk2():
    scan_file('bin/0511.efi', 'is_edk2')
    assert text_in_file('0511 is not from EDK2', 'bin/0511.brick')
