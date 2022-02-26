import pytest
import sys
sys.path.append('..')

from brick_api import scan_file

def text_in_file(text, filename):
    data = open(filename, 'r').read()
    return text in data

def test_toctou_pointer(session_dir):
    scan_file(f'{session_dir}/FirmwarePerformanceSmm.efi', 'toctou')
    assert text_in_file('ERROR (toctou.py)', f'{session_dir}/FirmwarePerformanceSmm.brick')

def test_toctou_not_pointer(session_dir):
    scan_file(f'{session_dir}/SmmFaultTolerantWriteDxe.efi', 'toctou')
    assert text_in_file('WARNING (toctou.py)', f'{session_dir}/SmmFaultTolerantWriteDxe.brick')
    assert not text_in_file('ERROR (toctou.py)', f'{session_dir}/SmmFaultTolerantWriteDxe.brick')