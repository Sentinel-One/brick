import pytest
import shutil

@pytest.fixture(scope='session')
def session_dir(tmpdir_factory):
    shutil.copytree('./bin', tmpdir_factory.getbasetemp(), dirs_exist_ok=True)
    return tmpdir_factory.getbasetemp()
    