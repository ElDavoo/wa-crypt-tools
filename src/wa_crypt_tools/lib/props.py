from __future__ import annotations

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.proto import backup_expiry_pb2 as backup_expiry

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
            self.max_feature = max(
                (int(name[2:]) for name in v_features.DESCRIPTOR.fields_by_name
                 if name.startswith("f_") and name[2:].isdigit()),
                default=C.DEFAULT_MAX_FEATURE)
            return
        self.props = backup_expiry.BackupExpiry()
        self.props.app_version = wa_version
        self.props.jidSuffix = jid
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

    def enable_feature(self, feature: int):
        feature_name = "f_" + str(feature)
        setattr(self.props, feature_name, True)

    def disable_feature(self, feature: int):
        feature_name = "f_" + str(feature)
        setattr(self.props, feature_name, False)

    def get_feature(self, feature: int) -> bool:
        feature_name = "f_" + str(feature)
        return getattr(self.props, feature_name)

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
        return self.props.jidSuffix

    def get_proto(self):
        return self.props

    def __str__(self):
        return str(self.props)