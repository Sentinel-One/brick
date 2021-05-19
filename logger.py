import time
import colorama
from contextlib import contextmanager

colorama.init(autoreset=True)

@contextmanager
def log_timing(msg):
    ellapsed = 0
    try:
        start = time.time()
        yield
        ellapsed = time.time() - start
    finally:
        print(colorama.Fore.CYAN + f'[#] {msg} took {int(ellapsed)} seconds')

@contextmanager
def log_step(msg):
    with log_timing(msg):
        try:
            print(colorama.Fore.YELLOW + '[=] ' + msg)
            yield
        finally:
            print(colorama.Fore.GREEN + '[*] Done ' + msg)

def log_operation(msg):
    print(colorama.Fore.MAGENTA + '[-] ' + msg)

def log_warning(msg):
    print(colorama.Fore.LIGHTRED_EX + '[!] ' + msg)

class BrickFormatter:

    def __init__(self, outfile) -> None:
        self.outfile = open(outfile, 'w')

    def write(self, text="", nl=True):
        if nl: text += "\n"
        self.outfile.write(text)

    def write_section_header(self, hdr):
        self.write('[*] ' + "-" * 50)
        self.write('[*] ' + hdr)
        self.write('[*] ' + "-" * 50)
        self.write()

    def write_entry(self, ent, data=None):
        if data is None:
            self.write(ent)
        else:
            self.write(ent)
            self.write('-' * 50)
            self.write(data, nl=False)

    def close(self):
        self.outfile.close()
