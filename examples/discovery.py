import sys
sys.path.append("../")

from pybose import BoseDiscovery

if __name__ == "__main__":
  discovery = BoseDiscovery()
  devices = discovery.discover_devices()
  for device in devices:
      print(f"GUID: {device['GUID']}, IP: {device['IP']}")