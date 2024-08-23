"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(_runtime_version.Domain.PUBLIC, 5, 27, 3, '', 'backup_prefix.proto')
_sym_db = _symbol_database.Default()
from . import C14_cipher_pb2 as C14__cipher__pb2
from . import C15_IV_pb2 as C15__IV__pb2
from . import key_type_pb2 as key__type__pb2
from . import backup_expiry_pb2 as backup__expiry__pb2
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13backup_prefix.proto\x1a\x10C14_cipher.proto\x1a\x0cC15_IV.proto\x1a\x0ekey_type.proto\x1a\x13backup_expiry.proto"\xa7\x01\n\x0cBackupPrefix\x12 \n\x08key_type\x18\x01 \x01(\x0e2\t.Key_TypeH\x01\x88\x01\x01\x12!\n\nc14_cipher\x18\x02 \x01(\x0b2\x0b.C14_cipherH\x00\x12\x19\n\x06c15_iv\x18\x03 \x01(\x0b2\x07.C15_IVH\x00\x12\x1b\n\x04info\x18\x04 \x01(\x0b2\r.BackupExpiryB\r\n\x0bcipher_infoB\x0b\n\t_key_typeb\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'backup_prefix_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals['_BACKUPPREFIX']._serialized_start = 93
    _globals['_BACKUPPREFIX']._serialized_end = 260