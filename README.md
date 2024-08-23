[![Coverage Status](https://coveralls.io/repos/github/ElDavoo/wa-crypt-tools/badge.svg?branch=main)](https://coveralls.io/github/ElDavoo/wa-crypt-tools?branch=main)

# WhatsApp Crypt Tools
Decrypt and encrypt WhatsApp and WA Business' .crypt12, .crypt14 and .crypt15 files with ease!  
For decryption, you NEED **the key file** or the 64-characters long key.  
The key file is named "key" if the backup is crypt14 or  
"encrypted_backup.key" if the backup is crypt15 (encrypted E2E backups).  
Those who are looking for a more complete suite for
WhatsApp forensics, check out [whapa.](https://github.com/B16f00t/whapa)

# Quick install

## Cloud - Google Colab

If you do not want to install programs in your computer, you can run this program
[in Google Colab](https://colab.research.google.com/drive/17z5UWE9dBbyvVfOG-KzRWCmTqFA3j82u?usp=sharing)
.  

## Local - Jupyter

If you are familiar with Jupyter (read 
[here](https://www.earthdatascience.org/courses/intro-to-earth-data-science/open-reproducible-science/jupyter-python/get-started-with-jupyter-notebook-for-python)
if you're not), you can use the
[notebook version](notebook.ipynb)
of the program.

## Local - pip

You can install this script as a package through pip. Just run:
```bash
python -m pip install git+https://github.com/ElDavoo/wa-crypt-tools
```

# Quick start

## Decrypt a file with wadecrypt
```
usage: wadecrypt [-h] [-nm] [-bs BUFFER_SIZE] [-nd] [-v] [-f] [keyfile] [encrypted] [decrypted]
```

So, for decrypting a crypt12/14/15, we give the program the key file, the encrypted file and the name of the output file.

### Example

```
$ wadecrypt encrypted_backup.key msgstore.db.crypt15 msgstore.db
key15.py:51     : [I] Crypt15 / Raw key loaded
wadecrypt.py:271        : [I] Done
```

## Encrypt a file with waencrypt (BETA)

```
usage: waencrypt [-h] [-f] [-v] [--enable-features [ENABLE_FEATURES ...]] [--max-feature MAX_FEATURE]
                 [--multi-file] [--type {12,14,15}] [--iv IV] [--reference REFERENCE] [--noparse]
                 [--wa-version WA_VERSION] [--jid JID] [--backup-version BACKUP_VERSION] [--no-compress]
                 [keyfile] [decrypted] [encrypted]
```

Encryption is more complex and untested: it is advised to use another encrypted file 
from the same account, which we will call "reference".  

### With a reference file (only database crypt15 tested)
```
waencrypt --reference msgstore.db.crypt15 encrypted_backup.key msgstore.db msgstore-new.db.crypt15
waencrypt.py:57         : [W] This script is in beta stage
waencrypt.py:89         : [I] Done!
```

### Without a reference file

You need to supply the following parameters:  

1) The feature list: Only for 2019+ databases. A list of numbered boolean
   properties related to your database. There is currently no way to infer them
   from a database file. In the example, we will just use my backup's feature list,
   but don't expect it to work for you.  
2) The max feature number, which is 39 at the time of writing
3) The version of the app that encrypted the file: Use a reasonable value,
   like 2.24.8.6 or something.  
4) Jid: The last 2 numbers of your phone number  
5) Backup version: Use 1.

Defaults will be used if parameters are omitted.  

To sum it up:
```
$ waencrypt --enable-features 5 6 7 8 9 10 11 12 13 14 15 16
 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 39 --type 15 --wa-version 2.26.1.2 --jid 00 --backup
-version 1 encrypted_backup.key msgstore.db msgstore-new.db.crypt15 
waencrypt.py:57         : [W] This script is in beta stage
waencrypt.py:89         : [I] Done!
```

You can get info about a backup file with the `wainfo` tool.

# Tool list
For usage, run the tool with `-h` option.
1) `wacreatekey` - Create key files
2) `wadecrypt` - Decrypt backups
3) `waencrypt` - Encrypt backups
4) `waguess` - Hacky way to try decrypt backups
5) `wainfo` - Get info about a backup 

# FAQ

## Can I decrypt a backup without a key file?

NO! What would be the point of encrypting a file otherwise?  

## I forgot the password / 64-letters key, can you help me?

See above.

## The program doesn't decrypt my backups and says the backups are corrupted

Your backups are corrupted. You can try disabling all checks with the
`-f` flag, but expect crashes and/or unreadable output.

## The program doesn't decrypt and says the key is wrong

The key is wrong. You can try disabling all checks with the
`-f` flag, but expect crashes and/or unreadable output.

## What is the best setup for decrypting my own databases?

1) Enable end-to-end backups and do NOT use a password, use the 64-letters key option.
2) Use `wacreatekey` to create a `encrypted_backup.key` file
3) Store your key file safely and use `wadecrypt` to decrypt your backups.

In this way, you will manage your own root key - otherwise WhatsApp might change 
your key when appropriate.  

## Can I use the password to decrypt the database?

No! The password is only used to talk with the WhatsApp servers and retrieve 
the 64-letters key.  
In other words, the password is used to **protect the key**, it's not used 
to encrypt the backups.  

## Can I decrypt .mcrypt1 files downloaded from Google Drive?
Yes, but the code is not documented, so please at this time read the code.  


## I really think the program is broken, that my backups are intact and that the key is right

Send me the needed files on Telegram and I will take a look.

If you (understandably) have privacy concerns, open an issue and attach:
1) Output of the program (both with and without --force)
2) Hexdump of keyfile
3) Hexdump of first 512 bytes of encrypted DB

But it will be more difficult to help you.  

## Where do I get the key(file)?
On a rooted Android device, you can just copy 
`/data/data/com.whatsapp/files/key` 
(or `/data/data/com.whatsapp/files/encrypted_backup.key` if backups are crypt15).  
If you enabled E2E backups, and you did not use a password 
(you have a copy of the 64-digit key, for example a screenshot), 
you can just transcribe and use it in lieu of the key file parameter.  
**There are other ways, but it is not in the scope of this project 
to tell you.  
Issues asking for this will be closed as invalid.**  
### I will happily accept pull requests for the currently open issues. :)

### Last tested version (don't expect this to be updated)
Stable: 
2.24.16.76  
Beta: 
2.24.18.10

#### Business
Stable:  
2.24.16.77

#### Protobuf automatic fix

You can install the proto optional dependencies to use `protoletariat` and fix the proto imports automatically.

First, after cloning the repository, do an editable installation of the package (possibily in a virtual environment) with:

`pip install -e .[proto]`

This will also install the optional dependencies of the package.

Next, download the protobuf compiler from its repository [here](https://github.com/protocolbuffers/protobuf/releases). 
You can move the protoc program to the `wa-crypt-tools/proto` folder where the .proto files are.
 
Replace the protobuf classes as needed and run `protoc` to generate the python classes. 
From the `wa-crypt-tools/proto` directory of the project, run:

`./protoc --python_out=../src/wa_crypt_tools/proto --proto_path=. *.proto`

After generating the protobuf python classes through `protoc`, from that same directory run:

`protol --in-place --python-out ..\src\wa_crypt_tools\proto protoc --proto-path=. *.proto`

Linux:  

`PATH="$(pwd):$PATH" protol --in-place --python-out ../src/wa_crypt_tools/proto protoc --proto-path=. *.proto`

Now all the generated python classes should have their imports fixed.

---

## Donations

Thank you so much to each one of you!
- **🎉🎉🎉 [githubsterer](https://github.com/githubsterer) 🎉🎉🎉** 
- **🎉🎉🎉 [courious875](https://github.com/courious875) 🎉🎉🎉**  
- **🎉 [pscriptos](https://github.com/pscriptos) 🎉**  

Anyone else that I forgot to mention!  
---

#### Credits:
 - Original implementation for crypt12: [TripCode](https://github.com/TripCode)    
 - Some help at the beginning: [DjEdu28](https://github.com/DjEdu28)  
 - Actual crypt14/15 implementation with protobuf: [ElDavoo](https://github.com/ElDavoo)  
 - Help with crypt14/15 footer: [george-lam](https://github.com/georg-lam)  
 - Pip package implementation: [Mikel12455](https://github.com/Mikel12455)  
 - [kingbtcvl](https://github.com/kingbtcvl)  

 Anyone else that helped!  


### Stargazers over time

[![Star History Chart](https://api.star-history.com/svg?repos=ElDavoo/wa-crypt-tools&type=Date)](https://star-history.com/#ElDavoo/wa-crypt-tools&Date)
