import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_set_variable_info_leak():
    scan_file('bin/0014.efi', 'setvar_infoleak')
    assert text_in_file('ERROR (setvar_infoleak.py)', 'bin/0014.brick')

def test_no_variable_calls():
    scan_file('bin/0017.efi', 'setvar_infoleak')
    assert text_in_file('SUCCESS (setvar_infoleak.py)', 'bin/0017.brick')

def test_no_potential_leaks():
    scan_file('bin/003b.efi', 'setvar_infoleak')
    assert text_in_file('SUCCESS (setvar_infoleak.py)', 'bin/003b.brick')
    