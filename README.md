# WhatsApp Crypt14 Database Decrypter
Decrypts WhatsApp msgstore.db.crypt14 files, **given the key file**.  
The output result is a SQLite database that you can read.  
This is the only thing this script does. Those who are looking for a complete suite for
WhatsApp foresincs, check out [whapa](https://github.com/B16f00t/whapa)
## Version 2.0 is here!
Since the file format keeps changing, I decided to completely reimplement the script.  
It should be much more efficient and "future proof" now,
as it tries to **automatically** find the various offsets instead of just failing,
does not create a temp file and does not load the encrypted DB in memory.  
(It still needs improvements, but it is ready for release :) )

## Where do I get the key?
On rooted Android, you can read  `/data/data/com.whatsapp/files/key`.  
**Is it not our job to tell you how to get the key file. Support will not given for this.**  

### Last tested version (don't expect this to be updated)
Stable: 2.21.24.22  
Beta: 2.22.1.10

### Not working / crash / etc

Please open an issue and attach:
1) Output of the program (both with and without force)
2) Hexdump of keyfile (without the last 32 bytes)
3) Hexdump of first 512 bytes of encrypted DB

Please also report if your offsets are too far (+-5)
from the default ones, which are:
1) t1 offset: 15
2) IV offset: 67
3) Data offset: 190 (or 191)

Changing the defaults makes the program more efficient.

#### To do / planned

1) Code reorganization (single file or more files?)
2) Code refactoring
3) Better parse unknown fields of DB and marriage key of keyfile

#### Not planned / wontfix

1) Support for encrypting
2) supporting older encryption formats

###### Usage
 ```
 decrypt14.py [-h] [-f] [keyfile] [encrypted] [decrypted]

Decrypts WhatsApp msgstore.db.crypt14 files

positional arguments:
  keyfile      The WhatsApp keyfile
  encrypted    The encrypted crypt14 database
  decrypted    The decrypted database

options:
  -h, --help   show this help message and exit
  -f, --force  Skip safety checks
  
  If decrypt fails and you use --force, 
  the program will 99% just spit more errors and crash.  
  However, trying does not cost anything.
 ```  
###### Requirements:

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
###### Credits:
 Authors: [TripCode](https://github.com/TripCode) & [ElDavoo](https://github.com/ElDavoo) & [DjEdu28](https://github.com/DjEdu28)
