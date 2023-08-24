from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.proto import version_features_pb2 as version_features

class Props:
    def __init__(self, *, wa_version: str = C.DEFAULT_WA_VERSION, jid: str = C.DEFAULT_JID,
                 features: list[int] = C.DEFAULT_FEATURE_LIST, max_feature: int = C.DEFAULT_MAX_FEATURE):
        self.props = version_features.Version_Features()
        self.props.whatsapp_version = wa_version
        self.props.substringedUserJid = jid
        for f in range(4, max_feature):
            self.disable_feature(f)
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
        for i in range(0, len(self.props.DESCRIPTOR.fields)):
            if self.get_feature(i):
                features.append(i)
        return features

    def get_wa_version(self) -> str:
        return self.props.version

    def get_jid(self) -> str:
        return self.props.jid

    def get_proto(self):
        return self.props

    def __str__(self):
        return str(self.props)