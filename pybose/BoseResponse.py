from typing import TypedDict, List, Optional


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
