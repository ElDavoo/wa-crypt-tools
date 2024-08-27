import os
from hashlib import sha512
from subprocess import Popen, STDOUT, PIPE

def Propen(command):
    if isinstance(command, str):
        command = command.split()
    # split the command string in a list
    p = Popen(command, stdout=PIPE, stderr=STDOUT, text=True)
    return p.communicate()[0], p.returncode

def cmp_files(file1: str, file2: str):
    with open(file1, 'rb') as f:
        keyb_digest = sha512(f.read()).digest()
    with open(file2, 'rb') as f:
        orig_check = sha512(f.read()).digest()
    return keyb_digest == orig_check

def rmifound(file: str):
    if not os.path.exists(file):
        return
    if not os.path.isfile(file):
        return
    try:
        os.remove(file)
    except FileNotFoundError:
        pass