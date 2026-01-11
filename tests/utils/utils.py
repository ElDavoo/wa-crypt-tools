import platform
import time
from pathlib import Path
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

def rm_if_found(file: str):
    path = Path(file)
    if not path.exists() or not path.is_file():
        return

    # On Windows, retry if file is locked by subprocess
    retries = 3 if platform.system() == 'Windows' else 1
    for attempt in range(retries):
        try:
            path.unlink(missing_ok=True)
            return
        except PermissionError:
            if attempt < retries - 1:
                time.sleep(0.1 * (attempt + 1))
            else:
                raise