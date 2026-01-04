# WhatsApp Crypt Tools - AI Coding Agent Instructions

## Project Overview
**wa-crypt-tools** is a Python utility for decrypting and encrypting WhatsApp backup files (.crypt12, .crypt14, .crypt15 formats). It supports three cryptographic versions with different key storage mechanisms and encryption parameters.

## Architecture Patterns

### Factory Pattern for Version Handling
The codebase uses two factory classes to abstract version-specific logic:

1. **KeyFactory** ([src/wa_crypt_tools/lib/key/keyfactory.py](src/wa_crypt_tools/lib/key/keyfactory.py))
   - Handles both file-based keys and hex string keys
   - Dispatches to Key14 or Key15 based on key format
   - Falls back gracefully with helpful error messages

2. **DatabaseFactory** ([src/wa_crypt_tools/lib/db/dbfactory.py](src/wa_crypt_tools/lib/db/dbfactory.py))
   - Detects crypt version (12/14/15) from file headers
   - Uses protobuf messages for crypt15 header parsing
   - Returns version-specific Database class (Database12/14/15)

Each version class inherits from base `Database` and `Key` classes, implementing version-specific encryption/decryption logic.

### Protobuf Integration for Crypt15
Crypt15 uses protobuf messages to parse backup headers:
- Definition files in [proto/](proto/) directory (backup_prefix.proto, C14_cipher.proto, C15_IV.proto, key_type.proto)
- Generated Python files in [src/wa_crypt_tools/proto/](src/wa_crypt_tools/proto/)
- **Critical dependency**: Requires protobuf ≥5.28.5 (failing imports suggest version mismatch)

## Command-Line Tools
All entry points in [src/wa_crypt_tools/](src/wa_crypt_tools/):

| Tool | Purpose |
|------|---------|
| **wadecrypt.py** | Decrypt crypt12/14/15 files; supports streaming with buffer control |
| **waencrypt.py** | Encrypt databases (BETA); requires reference file or complex parameters |
| **waguess.py** | Brute-force guess encryption keys |
| **wainfo.py** | Print metadata about encrypted/key files |
| **wacreatekey.py** | Generate new encryption keys |

Each tool:
- Configures logging via CustomFormatter ([src/wa_crypt_tools/lib/logformat.py](src/wa_crypt_tools/lib/logformat.py))
- Uses argparse for CLI argument parsing
- Sets up handlers for both root logger and `wa_crypt_tools.lib` logger

## Key Technical Details

### Decryption Process (wadecrypt.py)
- Uses AES GCM cipher with HMAC-SHA256 authentication
- Supports streaming/chunked reading to handle large files (buffer_size parameter)
- Handles three footer detection scenarios: single-file backup, multi-file backup, and split checksum
- Tests decompression using zlib; auto-detects ZIP vs. raw formats
- Verifies HMAC and detects corruption

### Critical Constants
See [src/wa_crypt_tools/lib/constants.py](src/wa_crypt_tools/lib/constants.py):
- `ZLIB_HEADERS`: Expected uncompressed data starts with `x\x01` or `PK`
- `HEADER_SIZE`: 384 bytes required for reliable header detection
- `DEFAULT_DATA_OFFSET`: 122 bytes (where encrypted data begins)
- `SUPPORTED_CIPHER_VERSION`: Only `b'\x00\x01'` supported
- `SUPPORTED_KEY_VERSIONS`: Keys support versions 1-3

### Logging Format
All tools use custom colored logging: `filename:lineno : [LEVEL] message`
- Enable debug with `-v` flag on CLI tools
- Levels: INFO (default), DEBUG, WARNING, ERROR, CRITICAL

## Testing

### Test Structure
- [tests/test_decrypt.py](tests/test_decrypt.py): Validates decryption against known test files using SHA512 hash
- [tests/test_encrypt.py](tests/test_encrypt.py): Tests encryption round-trips
- [tests/test_createkey.py](tests/test_createkey.py): Key generation and parsing
- [tests/lib/](tests/lib/): Unit tests for constants, utilities
- Test resources in [tests/res/](tests/res/): Contains test keys and encrypted databases

Run tests:
```bash
python -m pytest
```

### Test Data Files
- `tests/res/encrypted_backup.key`: Crypt15 E2E key (hex format)
- `tests/res/key`: Crypt12/14 key (binary, Java serialized)
- `tests/res/msgstore.db.crypt{12,14,15}`: Encrypted test databases

## Critical Dependencies

- **pycryptodomex ≥3.20.0**: AES-GCM encryption
- **protobuf ≥5.28.5 <6.0.0**
- **javaobj-py3 ≥0.4.4**: Parse Java serialized key objects (crypt12/14)

**Troubleshooting imports**:
- If protobuf import fails with "cannot import name 'builder'": Update protobuf to ≥3.20.0
- If no proto modules found: Download from [proto/](proto/) or run proto code generation

## Conventions & Patterns

1. **Logging**: Always use module-level logger: `log = logging.getLogger(__name__)`
2. **Error handling**: Use try/except with detailed log messages; avoid silent failures
3. **Versioning**: Pass version-specific context through factory; never check string filenames
4. **File I/O**: Use context managers (`with` statements); handle large files with streaming
5. **Checksum validation**: Always verify HMAC/authentication tags at end of decryption

## Extending the Codebase

- **Adding new crypt version**: Create `DatabaseXX.py` and `KeyXX.py` in respective lib folders; update factories
- **Modifying decryption logic**: Changes in base `Database` class affect all versions; test all three
- **Adding proto messages**: Update .proto files, regenerate Python code, update imports in db15.py
