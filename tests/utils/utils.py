from hashlib import sha512
from subprocess import Popen, STDOUT, PIPE

def Propen(command: str) -> tuple[str, int]:
    # split the command string in a list
    p = Popen(command.split(), stdout=PIPE, stderr=STDOUT, text=True)
    return p.communicate()[0], p.returncode

def cmp_files(file1: str, file2: str) -> bool:
    with open(file1, 'rb') as f:
        keyb_digest = sha512(f.read()).digest()
    with open(file2, 'rb') as f:
        orig_check = sha512(f.read()).digest()
    return keyb_digest == orig_check