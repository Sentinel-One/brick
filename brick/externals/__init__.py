from pathlib import Path

def get_external(name):
    return Path(__file__).parent / name