# WhatsApp Crypt14-15 Database Decrypter
Decrypts WhatsApp .crypt14 and .crypt15 files, **given the key file** or the 64-characters long key.  
The key file is named "key" if the backup is crypt14 or  
"encrypted_backup.key" if the backup is crypt15 (encrypted E2E backups).  
The output result is either a SQLite database 
or a ZIP file (in case of wallpapers and stickers).  
This is the only thing this script does. 
Those who are looking for a complete suite for
WhatsApp forensics, check out [whapa.](https://github.com/B16f00t/whapa)

## Requirements

**Remember to download the proto folder!**

Python 3.7 or more recent    
pycriptodome  
javaobj-py3  
protobuf  

Use:
 ```
              python -m pip install -r requirements.txt
 ```
  Or:
 ```
              python -m pip install pycryptodome javaobj-py3 protobuf
 ```

## Usage

 ```
usage: decrypt14_15.py [-h] [-f] [-nm] [-ng] [-np] [-ivo IV_OFFSET]
                       [-do DATA_OFFSET] [-v]
                       [keyfile] [encrypted] [decrypted]

Decrypts WhatsApp backup files encrypted with Crypt14 or Crypt15

positional arguments:
  keyfile               The WhatsApp encrypted_backup key file or the hex
                        encoded key. Default: encrypted_backup.key
  encrypted             The encrypted crypt15 or crypt14 file. Default:
                        msgstore.db.crypt15
  decrypted             The decrypted output file. Default: msgstore.db

options:
  -h, --help            show this help message and exit
  -f, --force           Makes errors non fatal. Default: false
  -nm, --no-mem         Does not load files in RAM, stresses the disk more.
                        Default: load files into RAM
  -ng, --no-guess       Does not try to guess the offsets, only protobuf
                        parsing.
  -np, --no-protobuf    Does not try to parse the protobuf message, only
                        offset guessing.
  -ivo IV_OFFSET, --iv-offset IV_OFFSET
                        The default offset of the IV in the encrypted file.
                        Only relevant in offset guessing mode. Default: 8
  -do DATA_OFFSET, --data-offset DATA_OFFSET
                        The default offset of the encrypted data in the
                        encrypted file. Only relevant in offset guessing mode.
                        Default: 122
  -v, --verbose         Prints all offsets and messages
 ```  

### Examples, with output
#### Crypt15
```  
python ./decrypt14_15.py ./encrypted_backup.key ./msgstore.db.crypt15 ./msgstore.db
[I] Crypt15 key loaded
[I] Database header parsed
[I] Decryption successful
```  
#### Crypt14
```  
python ./decrypt14_15.py ./key ./msgstore.db.crypt14 ./msgstore.db
[I] Crypt12/14 key loaded
[I] Database header parsed
[I] Decryption successful
```  
#### Crypt12 (unofficial)
```  
python ./decrypt14_15.py ./key ./msgstore.db.crypt12 ./msgstore.db -np -ivo 51 -do 67 
[I] Crypt12/14 key loaded
[I] WhatsApp version not found
[I] Offsets guessed (IV: 51, data: 67).
[I] Decryption successful
```

## I had to use --force to decrypt
Please open an issue.

## Not working / crash / etc

Please open an issue and attach:
1) Output of the program (both with and without --force)
2) Hexdump of keyfile
3) Hexdump of first 512 bytes of encrypted DB

### Will happily accept PR for:

1) Support for encrypting
2) supporting older encryption formats (you can decrypt crypt12 files using `--force` )

### Where do I get the keyfile?
On rooted Android, you can just copy 
`/data/data/com.whatsapp/files/key` 
(or `/data/data/com.whatsapp/files/encrypted_backup.key` if backups are crypt15).  
**There are other ways, but it is not in the scope of this project 
to tell you.  
Issues asking for this will be closed as invalid.**  

### Last tested version (don't expect this to be updated)
Stable: 2.22.4.74  
Beta: 2.22.5.13


### Stargazers over time

[![Stargazers over time](https://starchart.cc/ElDavoo/WhatsApp-Crypt14-Decrypter.svg)](https://starchart.cc/ElDavoo/WhatsApp-Crypt14-Decrypter)


###### Credits:
 Original implementation for crypt12: [TripCode](https://github.com/TripCode)    
 Some help at the beginning: [DjEdu28](https://github.com/DjEdu28)  
 Actual crypt14/15 implementation with protobuf: [ElDavoo](https://github.com/ElDavoo)
