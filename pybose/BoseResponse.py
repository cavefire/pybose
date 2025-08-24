from typing import TypedDict, List, Optional, Dict


class BoseHeaderMsgTypeEnum(enumerate):
    RESPONSE = "RESPONSE"
    NOTIFY = "NOTIFY"


class BoseHeader(TypedDict):
    device: str
    resource: str
    method: str
    msgtype: BoseHeaderMsgTypeEnum
    reqID: int
    version: float
    status: int
    token: str
    targetGuid: str


class BoseMessage(TypedDict):
    header: BoseHeader
    body: dict


# Capabilities
class CapabilityEndpoint(TypedDict):
    endpoint: str


class CapabilityGroup(TypedDict):
    apiGroup: str
    endpoints: List[CapabilityEndpoint]
    version: float


class Capabilities(TypedDict):
    group: list[CapabilityGroup]


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
    location: str
    name: str
    type: str


class ContainerCapabilities(TypedDict, total=False):
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
    capabilities: Optional[ContainerCapabilities]


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


# Active Groups
class ProductStateEnum(enumerate):
    WAITING = "WAITING"
    MASTER = "MASTER"


class ProductState(TypedDict):
    productId: str
    status: ProductStateEnum


class ProductRoleEnum(enumerate):
    NORMAL = "NORMAL"


class Product(TypedDict):
    productId: str
    role: ProductRoleEnum


class ActiveGroup(TypedDict):
    activeGroupId: str
    groupMasterId: str
    # groups: List[???]
    name: str
    productStates: List[ProductState]
    products: List[Product]


# System timeout
class SystemTimeout(TypedDict):
    noAudio: bool
    noVideo: bool


# CEC Settings
class CecSettingsSupportedValuesEnum(enumerate):
    ON = "ON"
    OFF = "OFF"
    ALTERNATE_ON = "ALTERNATE_ON"
    ALTMODE_3 = "ALTMODE_3"
    ALTMODE_4 = "ALTMODE_4"
    ALTMODE_5 = "ALTMODE_5"
    ALTMODE_6 = "ALTMODE_6"
    ALTMODE_7 = "ALTMODE_7"


class CecSettingsProperties(TypedDict, total=False):
    supportedModes: List[CecSettingsSupportedValuesEnum]


class CecSettings(TypedDict):
    mode: CecSettingsSupportedValuesEnum
    properties: CecSettingsProperties


# Product Settings
class PresetMetadata(TypedDict):
    accountID: str
    image: str
    name: str
    subType: str


class PresetContentItem(TypedDict):
    containerArt: str
    location: str
    name: str
    presetable: bool
    source: str
    sourceAccount: str
    type: str


class PresetActionPayload(TypedDict):
    contentItem: PresetContentItem


class PresetAction(TypedDict):
    actionType: str
    metadata: PresetMetadata
    payload: PresetActionPayload


class Preset(TypedDict):
    actions: List[PresetAction]


class Presets(TypedDict):
    presets: Dict[str, Preset]


class ProductProperties(TypedDict):
    supportedLanguages: List[str]


class ProductSettings(TypedDict):
    language: str
    ntpSyncDone: bool
    presets: Presets
    productName: str
    properties: ProductProperties
    timeformat: str
    timezone: str


class NetworkStateEnum(enumerate):
    DOWN = "DOWN"
    UP = "UP"


class NetworkTypeEnum(enumerate):
    WIRED_USB = "WIRED_USB"
    WIRED_ETH = "WIRED_ETH"
    WIRELESS = "WIRELESS"


class IpInfo(TypedDict):
    ipAddress: str
    subnetMask: str


class NetworkInterface(TypedDict):
    ipInfo: Optional[IpInfo]
    macAddress: str
    name: str
    state: NetworkStateEnum
    type: NetworkTypeEnum


class NetworkStatus(TypedDict):
    interfaces: List[NetworkInterface]
    isPrimaryUp: bool
    primary: str
    primaryIpAddress: str


# Bluetooth Device
class BluetoothDevice(TypedDict):
    deviceClass: str
    mac: str
    name: str


# Bluetooth Sink List
class BluetoothSinkList(TypedDict):
    devices: List[BluetoothDevice]


# Bluetooth Sink Status
class BluetoothSinkStatusEnum(enumerate):
    APP_PAIRABLE = "APP_PAIRABLE"
    APP_CONNECTED = "APP_CONNECTED"
    DEVICE_CONNECTING = "DEVICE_CONNECTING"
    DEVICE_DISCONNECTING = "DEVICE_DISCONNECTING"
    DEVICE_CONNECTED = "DEVICE_CONNECTED"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"


class BluetoothSinkStatus(TypedDict, total=False):
    activeDevice: str
    devices: List[BluetoothDevice]
    status: BluetoothSinkStatusEnum


# Bluetooth Source Status
class BluetoothSourceStatus(TypedDict):
    devices: List[BluetoothDevice]


# Bluetooth Connection Status (for notifications)
class BluetoothConnectionStatusEnum(enumerate):
    DEVICE_CONNECTING = "DEVICE_CONNECTING"
    DEVICE_DISCONNECTING = "DEVICE_DISCONNECTING"
    DEVICE_CONNECTED = "DEVICE_CONNECTED"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"


class BluetoothConnectionStatus(TypedDict):
    deviceClass: str
    mac: str
    name: str
    status: BluetoothConnectionStatusEnum


# Bluetooth Pair Status (for notifications)
class BluetoothPairStatusEnum(enumerate):
    PAIRING = "PAIRING"
    PAIRED = "PAIRED"
    UNPAIRED = "UNPAIRED"


class BluetoothPairStatus(TypedDict):
    mac: str
    status: BluetoothPairStatusEnum
