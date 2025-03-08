from typing import TypedDict, List, Optional, Dict


class V4VInput(TypedDict):
    input: str
    nameID: str


class Attributes(TypedDict, total=False):
    v4vInputs: List[V4VInput]


class PresetMetadata(TypedDict):
    accountID: str
    image: str
    name: str
    subType: str


class ContentItem(TypedDict):
    containerArt: str
    location: str
    name: str
    presetable: bool
    source: str
    sourceAccount: str
    type: str


class PresetPayload(TypedDict):
    contentItem: ContentItem


class PresetAction(TypedDict):
    actionType: str
    metadata: PresetMetadata
    payload: PresetPayload


class Preset(TypedDict):
    actions: List[PresetAction]


class ServiceAccountTokens(TypedDict, total=False):
    refresh_token: str
    refreshToken: str
    tokenType: str


class ServiceAccountAttributes(TypedDict, total=False):
    alexaEnv: str
    region: str
    WuWModel: str
    WuWord: str
    email: str
    language: str
    isDefaultAccount: bool


class ServiceAccount(TypedDict, total=False):
    accountID: str
    accountType: str
    bosePersonID: str
    createdOn: str
    provider: str
    providerAccountID: str
    tokens: ServiceAccountTokens
    updatedOn: str
    attributes: Optional[ServiceAccountAttributes]
    disabled: Optional[bool]
    name: Optional[str]
    productID: Optional[str]


class UserRole(TypedDict):
    role: str
    trustLevel: str


class Settings(TypedDict):
    language: str
    name: str
    sharingMode: str
    timeFormat: str
    timeZone: str


class BoseApiProduct(TypedDict):
    attributes: Attributes
    createdOn: str
    groups: List[str]
    persons: Dict[str, str]
    presets: Dict[str, Preset]
    productColor: int
    productID: str
    productType: str
    serviceAccounts: List[ServiceAccount]
    settings: Settings
    updatedOn: str
    users: Dict[str, UserRole]
