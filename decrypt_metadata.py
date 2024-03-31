import binascii
import hashlib
import hmac
from pathlib import Path

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.utils import mcrypt1_metadata_decrypt, get_mcrypt1_name
from wa_crypt_tools.lib.utils import encryptionloop

file_name = '239995BCE11E354151E3D5D85B0D48619708A999FADA4567AE5EB23153F9E7B4'
file_name_mcrypt = file_name + '.mcrypt1'
file_name_mcrypt_meta = file_name_mcrypt + '-metadata'
import base64

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def string_from_binary(binary):
    return binascii.a2b_base64(binary)


def main():
    with open("test-files/{}".format(file_name_mcrypt_meta), 'r') as f:
        metadata = f.read()
    # with open("test-files/{}-dec".format(file_name_meta), 'wb') as f:
    #    f.write(metadata)
    key = KeyFactory.from_file(Path("test/encrypted_backup.key"))
    decoded = mcrypt1_metadata_decrypt(key=key, encoded=metadata)
    print(decoded)
    media_hash = get_mcrypt1_name(key=key, name=decoded['name'], md5=decoded['md5Hash'])
    print(media_hash.hex())
    # Why?
    with open("test-files/{}".format(file_name_mcrypt), 'rb') as f:
        contents = f.read()
        sha256_orig = hashlib.sha256(contents).hexdigest()
        decrypted = mcrypt1_decrypt(key, media_hash, contents)
    recrypted = mcrypt1_encrypt(key, media_hash, decrypted)
    with open("test-files/{}-rec".format(file_name_mcrypt), 'wb') as f:
        f.write(recrypted)
    sha256_recrypted = hashlib.sha256(recrypted).hexdigest()
    print(sha256_orig)
    print(sha256_recrypted)
    print(sha256_orig == sha256_recrypted)


def mcrypt1_decrypt(key, media_hash, encrypted):
    derived_key = encryptionloop(first_iteration_data=key.get_root(),
                                 message=media_hash,
                                 outputBytes=48)
    secret_key = derived_key[:32]
    iv = derived_key[32:48]
    # Try to decrypt with AES GCM NoPadding
    cipher = AES.new(secret_key, AES.MODE_GCM, iv)
    return cipher.decrypt_and_verify(encrypted[:-16], encrypted[-16:])


def mcrypt1_encrypt(key, media_hash, data):
    derived_key = encryptionloop(first_iteration_data=key.get_root(),
                                 message=media_hash,
                                 outputBytes=48)
    secret_key = derived_key[:32]
    iv = derived_key[32:48]
    # Try to decrypt with AES GCM NoPadding
    cipher = AES.new(secret_key, AES.MODE_GCM, iv)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return encrypted + tag


if __name__ == '__main__':
    main()
