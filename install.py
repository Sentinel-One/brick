import requests
import shutil
import subprocess
import find_ida_user_dir
from brick.logger import log_operation, log_step
from collections import namedtuple
from pathlib import Path
import os
import shutil

DependencyDescriptor = namedtuple('DependencyDescriptor', ['name', 'source', 'target'])

def download_file(url, local_path):
    log_operation(f'Downloading {url} into {local_path}')
    
    dirname = os.path.dirname(local_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname)

    r = requests.get(url)
    open(local_path, 'wb').write(r.content)

def install_dependency(dep: DependencyDescriptor):
    log_operation(f'Installing {dep.name} into {dep.target}')
    if not dep.target.parent.exists():
        # Create intermediate directories, if necessary.
        os.makedirs(dep.target.parent)
    shutil.copy(dep.source, dep.target)

def install_ida_plugins():
    plugins_dir = Path(find_ida_user_dir.find_path('plugins'))
    deps_dir = Path(__file__).parent / 'deps'

    DEPENDENCIES = {
        # Codatify.
        # See 
        DependencyDescriptor(
            'codatify',
            deps_dir / 'codatify.py',
            plugins_dir / 'codatify.py'),
        
        # Rizzo.
        # See
        DependencyDescriptor(
            'rizzo',
            deps_dir / 'rizzo.py',
            plugins_dir / 'rizzo.py'),
        
        # AlleyCat
        # See
        DependencyDescriptor(
            'alleycat',
            deps_dir / 'alleycat.py',
            plugins_dir / 'alleycat.py'),
        
        # IDA shims
        # See
        DependencyDescriptor(
            'shims',
            deps_dir / 'ida_shims.py',
            plugins_dir / 'shims' / 'ida_shims.py'),
        
        # HexRaysCodeXplorer
        # See 
        DependencyDescriptor(
            'HexRaysCodeXplorer',
            deps_dir / 'HexRaysCodeXplorer' / 'HexRaysCodeXplorer.dll',
            plugins_dir / 'HexRaysCodeXplorer.dll'),
        
        DependencyDescriptor(
            'HexRaysCodeXplorer64',
            deps_dir / 'HexRaysCodeXplorer' / 'HexRaysCodeXplorer64.dll',
            plugins_dir / 'HexRaysCodeXplorer64.dll'),

        # efiXplorer
        # See
        DependencyDescriptor(
            'efiXplorer',
            deps_dir / 'efiXplorer' / 'efiXplorer.dll',
            plugins_dir / 'efiXplorer.dll'),

        DependencyDescriptor(
            'efiXplorer64',
            deps_dir / 'efiXplorer' / 'efiXplorer64.dll',
            plugins_dir / 'efiXplorer64.dll'),
    }

    for dep in DEPENDENCIES:
        install_dependency(dep)

def install_bip():
    try:
        bip_url = 'https://github.com/synacktiv/bip/archive/refs/heads/master.zip'
        download_file(bip_url, 'bip-master.zip')
        
        log_operation('Unpacking Bip')
        shutil.unpack_archive('bip-master.zip')

        log_operation('Installing Bip')
        subprocess.check_call('python bip-master/install.py')
    finally:
        log_operation('Removing temporary Bip files')
        os.remove('bip-master.zip')
        shutil.rmtree('bip-master')

def main():
    with log_step('Installing Bip'):
        install_bip()
    
    with log_step('Installing IDA plugins'):
        install_ida_plugins()

if __name__ == '__main__':
    main()