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