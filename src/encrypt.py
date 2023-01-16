import argparse
import hashlib
import os
import zlib

from src.lib.common_utils import SimpleLog
from src.lib.common_utils import import_aes
from src.lib.key import Key
import io

AES = import_aes()
import src.proto.prefix_pb2 as prefix_p
import src.proto.key_type_pb2 as key_type_p
import src.proto.C15_IV_pb2 as C15_IV_p
import src.proto.version_features_pb2 as version_features_p
def parsecmdline() -> argparse.Namespace:
    """Parses the command line arguments."""
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Encrypts a file in Crypt14 or Crypt15 format.')
    parser.add_argument('keyfile', nargs='?', type=str, default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file or the hex encoded key. '
                             'Default: encrypted_backup.key')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db",
                        help='The input file. Default: msgstore.db')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt15 or crypt14 file. Default: msgstore.db.crypt15')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Makes errors non fatal. Default: false')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')
    parser.add_argument('--msgstore', action='store_true', help='Encrypts a msgstore.db file')
    parser.add_argument('--multi-file', action='store_true', help='Encrypts a multi-file backup (either stickers or wallpapers)')
    # Add an argument "type" that can be either 14 or 15
    parser.add_argument('--type', type=int, choices=[14, 15], default=15, help='The type of encryption to use. Default: 15')
    parser.add_argument('--iv', type=str, help='The IV to use for crypt15 encryption. Default: random')
    parser.add_argument('--reference', type=argparse.FileType('rb'), help='The reference file to use for crypt15 encryption. Highly recommended.')
    parser.add_argument('--noparse', action='store_true', help='Do not parse the header of the reference file. Default: false')
    parser.add_argument('--wa-version', type=str, help='The WhatsApp version to use for crypt15 encryption. Default:')
    parser.add_argument('--jid', type=str, help='The last 4 numbers of your phone number. Default: 0000')
    parser.add_argument('--no-compress', action='store_true', help='Do not compress the file. This will make the backup not working. Only used in develpiomente. Default: false')
    return parser.parse_args()

def populate_info(info, is_crypt15 = True):
    # Put a constant version
    info.whatsapp_version = "2.23.1.11"
    # Put the last two numbers of the user's phone number
    info.substringedUserJid = "00"
    """
    For know there is no way to know the correct values for these fields.
    So it is strongly advised to have another encrypted msgstore,
    and to copy the values from there. This feature is not implemented yet.
    """
    if is_crypt15:
        # Iterate over all the features and set them to true
        for feature in info.DESCRIPTOR.fields:
            value = getattr(info, feature.name)
            if feature.type == feature.TYPE_BOOL:
                setattr(info, feature.name, True)
        info.feature_4 = False
        info.message_main_verification = False
        info.feature_37 = True
        info.feature_39 = False



def build_header(type, iv) -> bytes:
    # Create a new prefix object
    prefix = prefix_p.prefix()
    if type == 15:
        # Set the key type
        prefix.key_type = key_type_p.Key_Type.HSM_CONTROLLED
        # Write the C15_IV
        prefix.c15_iv.IV = iv
        # Set the version
        populate_info(prefix.info)
    else:
        # TODO
        raise NotImplementedError("Crypt14 is not implemented yet")

    return prefix.SerializeToString()


def from_reference_no_parse(logger, args, key, md5):
    # Read the first byte of the reference file
    protobuf_size = args.reference.read(1)
    md5.update(protobuf_size)
    args.encrypted.write(protobuf_size)
    protobuf_size = int.from_bytes(protobuf_size, byteorder='big')



    # It is my guess this is the backup type.
    # Looks like it is 1 for msgstore and 8 for other types.
    backup_type_raw = args.reference.read(1)
    backup_type = int.from_bytes(backup_type_raw, byteorder='big')
    if backup_type != 1:
        if backup_type == 8:
            logger.v("Not a (recent) msgstore database")
            # For some reason we need to go backward one byte
            args.reference.read.seek(-1, 1)
        else:
            logger.e("Unexpected backup type: {}".format(backup_type))
    else:
        if args.multi_file:
            logger.e("Reference file is a msgstore, but --multi-file is set")
        args.encrypted.write(backup_type_raw)
        md5.update(backup_type_raw)
    protobuf_raw = args.reference.read(protobuf_size)
    md5.update(protobuf_raw)
    args.encrypted.write(protobuf_raw)
    # We need the header to get the IV
    return protobuf_raw


def main():
    """Main function"""
    # Parse the command line arguments
    args = parsecmdline()
    # Create a new logger
    logger = SimpleLog(args.verbose, False)
    logger.i("This is still a work in progress, that will be completed in the future.")
    # Read the key file
    key = Key(logger, args.keyfile)
    # Start computing the MD5
    md5 = hashlib.md5()
    # Generate a random IV
    iv = os.urandom(16)
    # If specified, use the IV from the command line
    if args.iv:
        if args.reference is not None:
            #TODO for now we do not support this
            logger.e("Cannot specify both --iv and --reference")
        iv = bytes.fromhex(args.iv)
    if args.reference is not None:
        raw_haeder = from_reference_no_parse(logger, args, key, md5)
        # Parse the header to get the IV
        prefix = prefix_p.prefix()
        prefix.ParseFromString(raw_haeder)
        iv = prefix.c15_iv.IV
    else:
        from_scratch(args, md5, iv)
    # Create a new AES cipher
    cipher = AES.new(key.key, AES.MODE_GCM, iv)
    # Read the first 16 bytes of the decrypted file
    data = args.decrypted.read()
    # Compress the data
    # TODO make the compression as close as possible to the original
    # Currently it is not 100% the same
    compressed = zlib.compress(data, 1)
    # Encrypt the data
    if args.no_compress:
        encrypted = cipher.encrypt(data)
    else:
        encrypted = cipher.encrypt(compressed)
    # Update the MD5 with the encrypted data
    md5.update(encrypted)
    # Write the encrypted data
    args.encrypted.write(encrypted)

    tag = cipher.digest()
    # Write the authentication tag
    args.encrypted.write(tag)
    # Update the MD5 with the authentication tag
    md5.update(tag)
    # Write the MD5
    args.encrypted.write(md5.digest())
    # Close the files
    logger.i("Done!")
    args.decrypted.close()
    args.encrypted.close()


def from_scratch(args, md5, iv):
    # Create a new header
    header = build_header(args.type, iv)
    # Get the length of the header
    header_length = len(header).to_bytes(1)
    # Update the MD5 with the header length
    md5.update(header_length)
    # Write the header length
    args.encrypted.write(header_length)
    if args.msgstore:
        # Mistery byte
        args.encrypted.write(b'\x01')
        # Update the MD5 with the mistery byte
        md5.update(b'\x01')
    # Write the header
    args.encrypted.write(header)
    # Update the MD5 with the header
    md5.update(header)


if __name__ == '__main__':
    main()
