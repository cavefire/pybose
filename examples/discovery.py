from pybose import BoseDiscovery

# EXAMPLE USAGE

if __name__ == "__main__":
  discovery = BoseDiscovery()
  devices = discovery.discover_devices()
  for device in devices:
      print(f"GUID: {device['GUID']}, IP: {device['IP']}")