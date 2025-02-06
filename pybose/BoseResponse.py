""" This file contains classes used to make the handling of the local Bose API responses easier. """

class SystemInfo:
  """
  'countryCode': 'GB', 'defaultName': 'Bose Smart Ultra Soundbar', 'guid': '...', 'limitedFeatures': False, 'name': 'Bose Smart Ultra Soundbar', 'productColor': 1, 'productId': 16489, 'productName': 'Bose Smart Ultra Soundbar', 'productType': 'stevie', 'regionCode': 'GB', 'serialNumber': '...', 'softwareVersion': '...', 'variantId': 1
  """
  def __init__(self, data):
    self.countryCode = data.get("countryCode")
    self.defaultName = data.get("defaultName")
    self.limitedFeatures = data.get("limitedFeatures")
    self.name = data.get("name")
    self.productColor = data.get("productColor")
    self.productId = data.get("productId")
    self.productName = data.get("productName")
    self.productType = data.get("productType")
    self.regionCode = data.get("regionCode")
    self.serialNumber = data.get("serialNumber")
    self.softwareVersion = data.get("softwareVersion")
    self.variantId = data.get("variantId")
    
  def __str__(self):
    return f"{self.productName} ({self.productId}) - {self.softwareVersion}"
  
class AudioVolume:
  """
  {'defaultOn': 30, 'max': 70, 'min': 10, 'muted': False, 'properties': {'maxLimit': 100, 'maxLimitOverride': False, 'minLimit': 0, 'startupVolume': 30, 'startupVolumeOverride': False}, 'value': 10}
  """
  def __init__(self, data):
    self.defaultOn = data.get("defaultOn")
    self.max = data.get("max")
    self.min = data.get("min")
    self.muted = data.get("muted")
    self.properties = self.Properties(data.get("properties"))
    self.value = data.get("value")
    
  class Properties:
    def __init__(self, data):
      self.maxLimit = data.get("maxLimit")
      self.maxLimitOverride = data.get("maxLimitOverride")
      self.minLimit = data.get("minLimit")
      self.startupVolume = data.get("startupVolume")
      self.startupVolumeOverride = data.get("startupVolumeOverride")
      
class ContentNowPlaying:
  """
  {'container': {'contentItem': {'isLocal': True, 'presetable': False, 'source': 'INVALID_SOURCE'}}, 'source': {'sourceDisplayName': 'INVALID_SOURCE'}}
  
  {'collectData': True, 'container': {'capabilities': {'favoriteSupported': False, 'ratingsSupported': False, 'repeatSupported': False, 'resumeSupported': False, 'seekRelativeBackwardSupported': False, 'seekRelativeForwardSupported': False, 'shuffleSupported': False, 'skipNextSupported': True, 'skipPreviousSupported': True}, 'contentItem': {'containerArt': 'http://10.0.30.30/AirPlay2/ap2_01738071635.jpg', 'isLocal': True, 'presetable': False, 'source': 'AIRPLAY', 'sourceAccount': 'AirPlay2DefaultUserName'}}, 'initiatorID': '', 'metadata': {'album': '...', 'artist': '...', 'duration': 185, 'trackName': '...'}, 'source': {'sourceDisplayName': 'AirPlay', 'sourceID': 'AIRPLAY'}, 'state': {'canFavorite': False, 'canPause': True, 'canRate': False, 'canRepeat': False, 'canSeek': False, 'canShuffle': False, 'canSkipNext': True, 'canSkipPrevious': True, 'canStop': False, 'quality': 'NOT_SET', 'repeat': 'OFF', 'shuffle': 'OFF', 'status': 'PAUSED', 'timeIntoTrack': 11, 'timestamp': '2025-01-28T14:40:39+0100'}, 'track': {'contentItem': {'containerArt': 'http://.../AirPlay2/....jpg', 'isLocal': True, 'name': '...', 'presetable': False, 'source': 'AIRPLAY', 'sourceAccount': 'AirPlay2DefaultUserName'}, 'favorite': 'NO', 'rating': 'UNRATED'}}
  """
  def __init__(self, data):
    self.container = self.Container(data.get("container"))
    self.source = self.Source(data.get("source"))
    self.collectData = data.get("collectData")
    self.initiatorID = data.get("initiatorID")
    self.metadata = self.Metadata(data.get("metadata"))
    self.state = self.State(data.get("state"))
    self.track = self.Track(data.get("track"))

  class Container:
    def __init__(self, data):
      if data:
        self.contentItem = self.ContentItem(data.get("contentItem"))
        self.capabilities = self.Capabilities(data.get("capabilities"))

    class ContentItem:
      def __init__(self, data):
        if data:
            self.isLocal = data.get("isLocal")
            self.presetable = data.get("presetable")
            self.source = data.get("source")
            self.sourceAccount = data.get("sourceAccount")
            self.containerArt = data.get("containerArt")

    class Capabilities:
      def __init__(self, data):
        if data:
          self.favoriteSupported = data.get("favoriteSupported")
          self.ratingsSupported = data.get("ratingsSupported")
          self.repeatSupported = data.get("repeatSupported")
          self.resumeSupported = data.get("resumeSupported")
          self.seekRelativeBackwardSupported = data.get("seekRelativeBackwardSupported")
          self.seekRelativeForwardSupported = data.get("seekRelativeForwardSupported")
          self.shuffleSupported = data.get("shuffleSupported")
          self.skipNextSupported = data.get("skipNextSupported")
          self.skipPreviousSupported = data.get("skipPreviousSupported")

  class Source:
    def __init__(self, data):
      if data:
        self.sourceDisplayName = data.get("sourceDisplayName")
        self.sourceID = data.get("sourceID")

  class Metadata:
    def __init__(self, data):
      if data:
        self.album = data.get("album")
        self.artist = data.get("artist")
        self.duration = data.get("duration")
        self.trackName = data.get("trackName")

  class State:
    def __init__(self, data):
      if data:
        self.canFavorite = data.get("canFavorite")
        self.canPause = data.get("canPause")
        self.canRate = data.get("canRate")
        self.canRepeat = data.get("canRepeat")
        self.canSeek = data.get("canSeek")
        self.canShuffle = data.get("canShuffle")
        self.canSkipNext = data.get("canSkipNext")
        self.canSkipPrevious = data.get("canSkipPrevious")
        self.canStop = data.get("canStop")
        self.quality = data.get("quality")
        self.repeat = data.get("repeat")
        self.shuffle = data.get("shuffle")
        self.status = data.get("status")
        self.timeIntoTrack = data.get("timeIntoTrack")
        self.timestamp = data.get("timestamp")

  class Track:
    def __init__(self, data):
      if data:
        self.contentItem = ContentNowPlaying.Container.ContentItem(data.get("contentItem"))
        self.favorite = data.get("favorite")
        self.rating = data.get("rating")

  def __str__(self):
    return f"{self.metadata.artist} - {self.metadata.trackName}"
  
class SystemPowerControl:
  """
  {'power': 'ON'}
  """
  def __init__(self, data):
    self.power = data.get("power")

class Sources:
  def __init__(self, data):
    self.properties = self.Properties(data.get("properties"))
    self.sources = [self.Source(source) for source in data.get("sources")]

  class Properties:
    def __init__(self, data):
      self.supportedActivationKeys = data.get("supportedActivationKeys")
      self.supportedDeviceTypes = data.get("supportedDeviceTypes")
      self.supportedFriendlyNames = data.get("supportedFriendlyNames")
      self.supportedInputRoutes = data.get("supportedInputRoutes")

  class Source:
    def __init__(self, data):
      self.accountId = data.get("accountId")
      self.displayName = data.get("displayName")
      self.local = data.get("local")
      self.multiroom = data.get("multiroom")
      self.sourceAccountName = data.get("sourceAccountName")
      self.sourceName = data.get("sourceName")
      self.status = data.get("status")
      self.visible = data.get("visible")

  def __str__(self):
    return f"{self.sourceName} - {self.status}"

class Audio:
  def __init__(self, data):
    self.persistence = data.get("persistence")
    self.properties = self.Properties(data.get("properties"))
    self.value = data.get("value")

  class Properties:
    def __init__(self, data):
      self.max = data.get("max")
      self.min = data.get("min")
      self.step = data.get("step")
      self.supportedPersistence = data.get("supportedPersistence")

    def __str__(self):
      return f"{self.min} - {self.max} - {self.step}"

  def __str__(self):
    return f"{self.value}"
  
class Accessories:
  def __init__(self, data):
    self.controllable = self.Controllable(data.get("controllable"))
    self.enabled = self.Enabled(data.get("enabled"))
    self.pairing = data.get("pairing")
    self.rears = [self.Accessory(rear) for rear in data.get("rears")] if data.get("rears") else []
    self.subs = [self.Accessory(sub) for sub in data.get("subs")] if data.get("subs") else []

  class Controllable:
    def __init__(self, data):
      self.rears = data.get("rears")
      self.subs = data.get("subs")

  class Enabled:
    def __init__(self, data):
      self.rears = data.get("rears")
      self.subs = data.get("subs")

  class Accessory:
    def __init__(self, data):
      self.available = data.get("available")
      self.configurationStatus = data.get("configurationStatus")
      self.serialnum = data.get("serialnum")
      self.type = data.get("type")
      self.version = data.get("version")
      self.wireless = data.get("wireless")
      
class Battery:
  """{
    "chargeStatus": "DISCHARGING",
    "chargerConnected": "DISCONNECTED",
    "minutesToEmpty": 433,
    "minutesToFull": 65535,
    "percent": 42,
    "sufficientChargerConnected": false,
    "temperatureState": "NORMAL"
  }
  
  {
    "chargeStatus": "CHARGING",
    "chargerConnected": "CONNECTED",
    "minutesToEmpty": 441,
    "minutesToFull": 65535,
    "percent": 42,
    "sufficientChargerConnected": true,
    "temperatureState": "NORMAL"
  }""" 
  
  def __init__(self, data):    
    self.charging = data.get("chargeStatus") == "CHARGING"
    self.chargerConnected = data.get("chargerConnected") == "CONNECTED"
    self.minutesToEmpty = data.get("minutesToEmpty")
    self.minutesToFull = data.get("minutesToFull")
    self.percent = data.get("percent")
    self.sufficientChargerConnected = data.get("sufficientChargerConnected")
    self.temperatureNormal = data.get("temperatureState") == "NORMAL"
    
  def __str__(self):
    return f"{self.percent}%"