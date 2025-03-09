import os
import time
import pytest
from pybose.BoseDiscovery import BoseDiscovery

@pytest.mark.integration
def test_discover_devices_with_bose_gwid():
    """
    Integration test for device discovery using Zeroconf.
    If the environment variable BOSE_GWID is set, the test verifies that at least one discovered device's GUID matches it.
    """
    gwid = os.environ.get("BOSE_GWID")
    if not gwid:
        pytest.skip("BOSE_GWID environment variable not set. Skipping device discovery integration test.")
    discovery = BoseDiscovery()
    # Use a slightly longer timeout for real network discovery
    devices = discovery.discover_devices(timeout=10)
    # Optionally log discovered devices
    print("Discovered devices:", devices)
    matching_devices = [device for device in devices if device.get("GUID") == gwid]
    assert matching_devices, f"No discovered device has GUID {gwid}"

@pytest.mark.integration
def test_discover_devices_returns_list():
    """
    Integration test to simply ensure that the discover_devices method returns a list.
    This test runs even if BOSE_GWID is not set.
    """
    discovery = BoseDiscovery()
    devices = discovery.discover_devices(timeout=5)
    assert isinstance(devices, list), "discover_devices did not return a list"