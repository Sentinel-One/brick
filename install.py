import requests
import shutil
import subprocess
import find_ida_user_dir
from logger import log_operation, log_step
from collections import namedtuple
from pathlib import Path
import os

def download_file(url, local_path):
    log_operation(f'Downloading {url} into {local_path}')
    
    dirname = os.path.dirname(local_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname)

    r = requests.get(url)
    open(local_path, 'wb').write(r.content)

def install_ida_plugins():
    plugins_dir = Path(find_ida_user_dir.find_path('plugins'))

    IDAPlugin = namedtuple('Plugin', ['name', 'remote_url', 'local_path'])

    PLUGINS = {
        IDAPlugin('codatify', 'https://raw.githubusercontent.com/tacnetsol/ida/master/plugins/codatify/codatify.py', plugins_dir / 'codatify.py'),
        IDAPlugin('rizzo', 'https://raw.githubusercontent.com/tacnetsol/ida/master/plugins/rizzo/rizzo.py', plugins_dir / 'rizzo.py'),
        IDAPlugin('alleycat', 'https://raw.githubusercontent.com/tacnetsol/ida/master/plugins/alleycat/alleycat.py', plugins_dir / 'alleycat.py'),
        IDAPlugin('shims', 'https://raw.githubusercontent.com/tacnetsol/ida/master/plugins/shims/ida_shims.py', plugins_dir / 'shims' / 'ida_shims.py'),
    }

    for plugin in PLUGINS:
        log_operation(f'Installing {plugin.name}')
        download_file(plugin.remote_url, plugin.local_path)

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