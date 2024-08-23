"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(_runtime_version.Domain.PUBLIC, 5, 27, 3, '', 'C14_cipher.proto')
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10C14_cipher.proto"m\n\nC14_cipher\x12\x16\n\x0ecipher_version\x18\x01 \x01(\x0c\x12\x13\n\x0bkey_version\x18\x02 \x01(\x0c\x12\x13\n\x0bserver_salt\x18\x03 \x01(\x0c\x12\x11\n\tgoogle_id\x18\x04 \x01(\x0c\x12\n\n\x02IV\x18\x05 \x01(\x0cb\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'C14_cipher_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals['_C14_CIPHER']._serialized_start = 20
    _globals['_C14_CIPHER']._serialized_end = 129