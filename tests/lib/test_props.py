"""
Props: the BackupExpiry protobuf that encryption needs and a plaintext database cannot supply.
"""

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.props import Props


class TestProps:
    def test_the_defaults_come_from_the_constants(self):
        props = Props()
        assert props.get_jid() == C.DEFAULT_JID_SUFFIX
        assert props.get_proto().app_version == C.DEFAULT_APP_VERSION
        # DEFAULT_MAX_FEATURE is 39, but field 38 is backup_export_file_size and not a flag at
        # all, so walking 5..39 has to survive the gap rather than blowing up on it.
        assert props.get_features() == C.DEFAULT_FEATURE_LIST
        assert 38 not in props.get_features()

    def test_features_are_the_ones_asked_for_and_no_others(self):
        props = Props(features=[5, 7, 13], max_feature=37)
        assert props.get_features() == [5, 7, 13]
        assert props.get_feature(5) is True
        assert props.get_feature(6) is False

    def test_enable_and_disable(self):
        props = Props(features=[5], max_feature=37)
        props.enable_feature(9)
        assert props.get_features() == [5, 9]
        props.disable_feature(5)
        assert props.get_features() == [9]

    def test_no_features_leaves_the_table_out(self):
        # This is what makes a msgstore-noexpiry backup: the header carries no feature flags,
        # and Database14.encrypt keys off the empty list to drop the 0x01 marker byte.
        props = Props(features=None)
        assert props.get_features() == []
        assert props.get_proto().backup_version == 0

    def test_an_empty_feature_list_is_the_same_as_none(self):
        assert Props(features=[]).get_features() == []

    def test_a_parsed_header_is_wrapped_as_is(self):
        from wa_crypt_tools.proto import backup_expiry_pb2 as backup_expiry

        parsed = backup_expiry.BackupExpiry()
        parsed.app_version = "2.22.5.13"
        parsed.jid_suffix = "67"
        parsed.call_log_migration_finished = True
        props = Props(v_features=parsed)
        assert props.get_proto() is parsed
        assert props.get_jid() == "67"

    def test_features_are_readable_off_a_parsed_header_too(self):
        # Props(v_features=...) is how DatabaseFactory wraps a header it has just parsed.
        # It never set max_feature, so get_features() -- the only thing that reads it --
        # raised AttributeError on every props built that way.
        from wa_crypt_tools.proto import backup_expiry_pb2 as backup_expiry

        parsed = backup_expiry.BackupExpiry()
        parsed.call_log_migration_finished = True
        parsed.receipt_user_migration_finished = True
        parsed.cleaned_db = True
        assert Props(v_features=parsed).get_features() == [5, 13, 39]

    def test_wa_version_and_jid_are_kept(self):
        props = Props(wa_version="2.22.5.13", jid="67", features=[5], max_feature=37)
        assert props.get_jid() == "67"
        assert props.get_wa_version() == "2.22.5.13"
        assert props.get_proto().app_version == "2.22.5.13"

    def test_wa_version_is_readable_off_a_parsed_header_too(self):
        # get_wa_version used to read a "version" field the protobuf does not have, so it
        # raised AttributeError for every caller.
        from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory

        with open("tests/res/msgstore.db.crypt15", "rb") as f:
            assert DatabaseFactory.from_file(f).props.get_wa_version() == "2.22.5.13"

    def test_str_is_the_protobuf_text_format(self):
        string = str(Props(wa_version="2.22.5.13", jid="67", features=[5], max_feature=37))
        assert 'app_version: "2.22.5.13"' in string
        assert "call_log_migration_finished: true" in string
