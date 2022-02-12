import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_double_fetch():
    scan_file('bin/FirmwarePerformanceSmm.efi', 'toctou')
    assert text_in_file('ERROR (toctou.py)', 'bin/FirmwarePerformanceSmm.brick')

