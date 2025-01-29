from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
from typing import List, Dict

class BoseDiscovery:
  """ Discover Bose devices on the local network using Zeroconf. """
  def __init__(self, zeroconf: Zeroconf = None):
    if zeroconf is None:
      zeroconf = Zeroconf()
    self.zeroconf = zeroconf
    self.devices: List[Dict[str, str]] = []

  def _on_service_state_change(self, zeroconf, service_type, name, state_change):
    if state_change == ServiceStateChange.Added:
      self._resolve_service(name)

  def _resolve_service(self, name: str):
    info = self.zeroconf.get_service_info("_bose-passport._tcp.local.", name)
    if info:
      guid = info.properties.get(b"GUID")
      if guid:
        guid = guid.decode("utf-8")
      addresses = [addr for addr in info.parsed_addresses()]
      if addresses:
        self.devices.append({"GUID": guid, "IP": addresses[0]})

  def discover_devices(self, timeout: int = 5) -> List[Dict[str, str]]:
    """
    Discover devices in the `_bose-passport._tcp.local` service and return their GUID and IP address.

    :param timeout: Time in seconds to wait for discovery.
    :return: List of dictionaries containing GUID and IP for each discovered device.
    """
    self.devices = []

    listener = ServiceBrowser(self.zeroconf, "_bose-passport._tcp.local.", handlers=[self._on_service_state_change])

    try:
        import time
        time.sleep(timeout)
    finally:
        self.zeroconf.close()

    return self.devices

# EXAMPLE USAGE

if __name__ == "__main__":
  discovery = BoseDiscovery()
  devices = discovery.discover_devices()
  for device in devices:
      print(f"GUID: {device['GUID']}, IP: {device['IP']}")