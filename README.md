# WhatsApp Crypt14 Database Decrypter
Decrypts WhatsApp msgstore.db.crypt14 files, **given the key file**.  
The output result is a SQLite database.  
This is the only thing this script does. Those who are looking for a complete suite for
WhatsApp forensics, check out [whapa.](https://github.com/B16f00t/whapa)

## Version 2.0 is here!
Since the file format keeps changing, I decided to completely reimplement the script.  
It should be much more efficient, and it should handle small variations of offset **automatically**.

## Requirements:

Python 3.x (developed with 3.10)    
pycriptodome  

Use:
 ```
              python -m pip install -r requirements.txt
 ```
  Or:
 ```
              python -m pip install pycryptodome
 ```

## Usage
 ```
usage: decrypt14.py [-h] [-f] [-nm] [-v] [keyfile] [encrypted] [decrypted]

Decrypts WhatsApp encrypted database backup files

positional arguments:
  keyfile        The WhatsApp keyfile. Default: key
  encrypted      The encrypted crypt14 database. Default: msgstore.db.crypt14
  decrypted      The decrypted output database file. Default: msgstore.db

options:
  -h, --help     show this help message and exit
  -f, --force    Makes errors non fatal. Default: false
  -nm, --no-mem  Does not load files in RAM,stresses the disk more. Default:
                 load files into RAM
  -v, --verbose  Prints all offsets and messages
 ```  


## Not working / crash / etc

Please open an issue and attach:
1) Output of the program (both with and without --force)
2) Hexdump of keyfile
3) Hexdump of first 512 bytes of encrypted DB

Please also report if your offsets are too far (+-5)
from the default ones, which are:
1) t1 offset: 15
2) IV offset: 67
3) Data offset: 190 (or 191)

Changing the defaults makes the program more efficient.

### Not planned / wontfix

1) Support for encrypting
2) supporting older encryption formats

### Where do I get the keyfile?
**Is it beyond the scope of this project to tell you how to get the key file.  
Issues asking for this will be closed as invalid.**  
Anyway, on rooted Android, you can just copy  `/data/data/com.whatsapp/files/key`.  

### Last tested version (don't expect this to be updated)
Stable: 2.21.24.22  
Beta: 2.22.1.10

###### Credits:
 Authors: [TripCode](https://github.com/TripCode) & [ElDavoo](https://github.com/ElDavoo) & [DjEdu28](https://github.com/DjEdu28)
