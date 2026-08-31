from __future__ import annotations

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.proto import backup_expiry_pb2 as backup_expiry

def _highest_feature(descriptor) -> int:
    """
    The largest field number that is a migration flag.

    These are the numbers this project calls features. Reading them off the schema rather than
    hardcoding 39 means the range keeps up on its own when the proto grows another flag.
    """
    return max((f.number for f in descriptor.fields if f.type == f.TYPE_BOOL),
               default=C.DEFAULT_MAX_FEATURE)


class Props:
    def __init__(self, *, v_features=None, wa_version: str = C.DEFAULT_APP_VERSION, jid: str = C.DEFAULT_JID_SUFFIX,
                 features: list[int] | None = C.DEFAULT_FEATURE_LIST, max_feature: int = C.DEFAULT_MAX_FEATURE,
                 backup_version: int = C.DEFAULT_BACKUP_VERSION):
        if v_features is not None:
            self.props = v_features
            # max_feature is not part of the protobuf -- it is only how far get_features()
            # counts -- so a props built from a parsed header has to get one from somewhere
            # or every call raises AttributeError. The schema itself is the answer, and
            # reading it here means this keeps up when the proto grows a feature.
            self.max_feature = _highest_feature(v_features.DESCRIPTOR)
            return
        self.props = backup_expiry.BackupExpiry()
        self.props.app_version = wa_version
        self.props.jid_suffix = jid
        self.max_feature = max_feature
        if features is None or len(features) == 0:
            return
        self.props.backup_version = backup_version
        for f in range(5, max_feature + 1):
            try:
                self.disable_feature(f)
            except AttributeError:
                pass
        for f in features:
            self.enable_feature(f)

    def _feature_name(self, feature: int) -> str:
        """The schema's name for the flag with this number, or AttributeError if there is none."""
        field = self.props.DESCRIPTOR.fields_by_number.get(feature)
        if field is None or field.type != field.TYPE_BOOL:
            raise AttributeError("No feature numbered {}".format(feature))
        return field.name

    def enable_feature(self, feature: int):
        setattr(self.props, self._feature_name(feature), True)

    def disable_feature(self, feature: int):
        setattr(self.props, self._feature_name(feature), False)

    def get_feature(self, feature: int) -> bool:
        return getattr(self.props, self._feature_name(feature))

    def get_features(self) -> list[int]:
        features = []
        for i in range(5, self.max_feature + 1):
            try:
                if self.get_feature(i):
                    features.append(i)
            except AttributeError:
                pass
        return features

    def get_wa_version(self) -> str:
        return self.props.app_version

    def get_jid(self) -> str:
        return self.props.jid_suffix

    def get_proto(self):
        return self.props

    def __str__(self):
        return str(self.props)