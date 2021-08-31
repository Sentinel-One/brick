import time
import datetime
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
        delta = datetime.timedelta(seconds=ellapsed)
        print(colorama.Fore.CYAN + f'[#] {msg} took {delta}')

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
