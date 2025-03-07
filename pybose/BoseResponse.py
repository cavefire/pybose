from typing import TypedDict, List, Optional, Dict


# SystemInfo
class SystemInfo(TypedDict):
    countryCode: str
    defaultName: str
    limitedFeatures: bool
    name: str
    productColor: int
    productId: int
    productName: str
    productType: str
    regionCode: str
    serialNumber: str
    softwareVersion: str
    variantId: int


# AudioVolume
class VolumeProperties(TypedDict):
    maxLimit: int
    maxLimitOverride: bool
    minLimit: int
    startupVolume: int
    startupVolumeOverride: bool


class AudioVolume(TypedDict):
    defaultOn: int
    max: int
    min: int
    muted: bool
    properties: VolumeProperties
    value: int


# ContentNowPlaying
class ContentItem(TypedDict, total=False):
    isLocal: bool
    presetable: bool
    source: str
    sourceAccount: str
    containerArt: str


class Capabilities(TypedDict, total=False):
    favoriteSupported: bool
    ratingsSupported: bool
    repeatSupported: bool
    resumeSupported: bool
    seekRelativeBackwardSupported: bool
    seekRelativeForwardSupported: bool
    shuffleSupported: bool
    skipNextSupported: bool
    skipPreviousSupported: bool


class Container(TypedDict, total=False):
    contentItem: Optional[ContentItem]
    capabilities: Optional[Capabilities]


class Source(TypedDict, total=False):
    sourceDisplayName: str
    sourceID: str


class Metadata(TypedDict, total=False):
    album: str
    artist: str
    duration: int
    trackName: str


class State(TypedDict, total=False):
    canFavorite: bool
    canPause: bool
    canRate: bool
    canRepeat: bool
    canSeek: bool
    canShuffle: bool
    canSkipNext: bool
    canSkipPrevious: bool
    canStop: bool
    quality: str
    repeat: str
    shuffle: str
    status: str
    timeIntoTrack: int
    timestamp: str


class Track(TypedDict, total=False):
    contentItem: Optional[ContentItem]
    favorite: str
    rating: str


class ContentNowPlaying(TypedDict, total=False):
    collectData: bool
    container: Optional[Container]
    source: Optional[Source]
    initiatorID: str
    metadata: Optional[Metadata]
    state: Optional[State]
    track: Optional[Track]


# System Power Control
class SystemPowerControl(TypedDict):
    power: str


# Sources
class SourceData(TypedDict, total=False):
    accountId: str
    displayName: str
    local: bool
    multiroom: bool
    sourceAccountName: str
    sourceName: str
    status: str
    visible: bool


class SourceProperties(TypedDict, total=False):
    supportedActivationKeys: List[str]
    supportedDeviceTypes: List[str]
    supportedFriendlyNames: List[str]
    supportedInputRoutes: List[str]


class Sources(TypedDict):
    properties: SourceProperties
    sources: List[SourceData]


# Audio
class AudioProperties(TypedDict, total=False):
    max: int
    min: int
    step: int
    supportedPersistence: bool


class Audio(TypedDict, total=False):
    persistence: bool
    properties: Optional[AudioProperties]
    value: int


# Accessories
class AccessoryData(TypedDict, total=False):
    available: bool
    configurationStatus: str
    serialnum: str
    type: str
    version: str
    wireless: bool


class Accessories(TypedDict, total=False):
    controllable: Optional[dict]
    enabled: Optional[dict]
    pairing: bool
    rears: Optional[List[AccessoryData]]
    subs: Optional[List[AccessoryData]]


# Battery
class Battery(TypedDict, total=False):
    chargeStatus: str
    chargerConnected: str
    minutesToEmpty: int
    minutesToFull: int
    percent: int
    sufficientChargerConnected: bool
    temperatureState: str


# AudioMode
class AudioModeProperties(TypedDict, total=False):
    supportedPersistence: List[str]
    supportedValues: List[str]


class AudioMode(TypedDict):
    persistence: str
    properties: AudioModeProperties
    value: str


# Dual Mono Settings
class DualMonoSettingsProperties(TypedDict, total=False):
    supportedValues: List[str]


class DualMonoSettings(TypedDict):
    value: str
    properties: DualMonoSettingsProperties


# Rebroadcast Latency Mode
class RebroadcastLatencyModeProperties(TypedDict, total=False):
    supportedModes: List[str]


class RebroadcastLatencyMode(TypedDict):
    mode: str
    properties: RebroadcastLatencyModeProperties


"""Bose cloud api responses:"""


# V4V Input
class V4VInput(TypedDict):
    input: str
    nameID: str


class Attributes(TypedDict, total=False):
    v4vInputs: List[V4VInput]


# Preset Metadata & Payload
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


# Service Accounts & Tokens
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


# Users
class UserRole(TypedDict):
    role: str
    trustLevel: str


# Settings
class Settings(TypedDict):
    language: str
    name: str
    sharingMode: str
    timeFormat: str
    timeZone: str


# Main Data Structure
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
