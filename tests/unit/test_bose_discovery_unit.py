import time
import pytest
from unittest.mock import patch
from zeroconf import ServiceStateChange

from pybose.BoseDiscovery import BoseDiscovery

# Fake service info object with the minimal interface required.
class FakeServiceInfo:
    def __init__(self, guid: bytes, addresses):
        self.properties = {b"GUID": guid}
        self._addresses = addresses

    def parsed_addresses(self):
        return self._addresses

# Fake Zeroconf object for testing
class FakeZeroconf:
    def __init__(self, service_info=None):
        self.service_info = service_info

    def get_service_info(self, service_type, name):
        # For testing, if the requested name is "FakeService", return our fake info.
        if name == "FakeService":
            return self.service_info
        return None

    def close(self):
        pass

# Fake ServiceBrowser that immediately simulates a service added event.
class FakeServiceBrowser:
    def __init__(self, zeroconf, service_type, handlers):
        # Immediately trigger each handler with a fake event.
        for handler in handlers:
            handler(zeroconf, service_type, "FakeService", ServiceStateChange.Added)

# Test _resolve_service: when service info is returned, the device should be added.
def test_resolve_service_success():
    fake_info = FakeServiceInfo(guid=b"test-guid", addresses=["192.168.1.100"])
    fake_zeroconf = FakeZeroconf(service_info=fake_info)
    discovery = BoseDiscovery(zeroconf=fake_zeroconf)
    discovery._resolve_service("FakeService")
    assert discovery.devices == [{"GUID": "test-guid", "IP": "192.168.1.100"}]

# Test _resolve_service: when get_service_info returns None, no device is added.
def test_resolve_service_no_info():
    fake_zeroconf = FakeZeroconf(service_info=None)
    discovery = BoseDiscovery(zeroconf=fake_zeroconf)
    discovery._resolve_service("FakeService")
    assert discovery.devices == []

# Test _on_service_state_change: when state is Added, _resolve_service should be called.
def test_on_service_state_change_added():
    fake_zeroconf = FakeZeroconf(service_info=None)
    discovery = BoseDiscovery(zeroconf=fake_zeroconf)
    with patch.object(discovery, "_resolve_service") as mock_resolve:
        discovery._on_service_state_change(fake_zeroconf, "_bose-passport._tcp.local.", "FakeService", ServiceStateChange.Added)
        mock_resolve.assert_called_once_with("FakeService")

# Test _on_service_state_change: when state is not Added, _resolve_service is not called.
def test_on_service_state_change_not_added():
    fake_zeroconf = FakeZeroconf(service_info=None)
    discovery = BoseDiscovery(zeroconf=fake_zeroconf)
    with patch.object(discovery, "_resolve_service") as mock_resolve:
        discovery._on_service_state_change(fake_zeroconf, "_bose-passport._tcp.local.", "FakeService", ServiceStateChange.Removed)
        mock_resolve.assert_not_called()

# Test discover_devices: using our FakeServiceBrowser to simulate service discovery.
def test_discover_devices():
    fake_info = FakeServiceInfo(guid=b"fake-guid", addresses=["10.0.0.1"])
    fake_zeroconf = FakeZeroconf(service_info=fake_info)
    # Patch ServiceBrowser in the BoseDiscovery module so it uses our FakeServiceBrowser.
    with patch("pybose.BoseDiscovery.ServiceBrowser", new=FakeServiceBrowser):
        discovery = BoseDiscovery(zeroconf=fake_zeroconf)
        # Patch time.sleep to avoid actual waiting.
        with patch("pybose.BoseDiscovery.time.sleep", return_value=None):
            devices = discovery.discover_devices(timeout=0)
    assert devices == [{"GUID": "fake-guid", "IP": "10.0.0.1"}]