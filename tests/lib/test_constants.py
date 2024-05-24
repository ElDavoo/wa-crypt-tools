from wa_crypt_tools.lib.constants import C


class TestConstants:
    def test_zip_header(self):
        assert C.ZIP_HEADER == b'PK\x03\x04'
