"""
BoseDiscovery Module

This module provides functionality to discover Bose devices on the local network using Zeroconf.
It scans for devices broadcasting the "_bose-passport._tcp.local." service and extracts key
information such as the device GUID and IP address.
"""

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange
from typing import List, Dict
import time


class BoseDiscovery:
    """
    Discover Bose devices on the local network using Zeroconf.

    This class creates a Zeroconf instance (if not provided) and listens for devices
    advertising the "_bose-passport._tcp.local." service. When a service is added, it resolves
    the service to extract the device's GUID and IP address.

    Attributes:
        zeroconf (Zeroconf): The Zeroconf instance used for network discovery.
        devices (List[Dict[str, str]]): A list of discovered devices with keys "GUID" and "IP".
    """

    def __init__(self, zeroconf: Zeroconf = None) -> None:
        """
        Initialize a BoseDiscovery instance.

        If no Zeroconf instance is provided, a new one is created.

        Args:
            zeroconf (Optional[Zeroconf]): An optional Zeroconf instance to use.
        """
        if zeroconf is None:
            zeroconf = Zeroconf()
        self.zeroconf = zeroconf
        self.devices: List[Dict[str, str]] = []

    def _on_service_state_change(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange) -> None:
        """
        Callback invoked on service state changes.

        When a new service is added, this method calls the _resolve_service method
        to process the service details.

        Args:
            zeroconf (Zeroconf): The Zeroconf instance triggering the callback.
            service_type (str): The type of service that changed.
            name (str): The name of the service.
            state_change (ServiceStateChange): The state change (e.g., Added, Removed).
        """
        if state_change == ServiceStateChange.Added:
            self._resolve_service(name)

    def _resolve_service(self, name: str) -> None:
        """
        Resolve the details of a discovered service.

        Retrieves service information for the "_bose-passport._tcp.local." service using the provided name.
        If the service contains a "GUID" property and at least one IP address, it appends a dictionary with
        the GUID and the first IP address to the devices list.

        Args:
            name (str): The name of the service to resolve.
        """
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
        Discover Bose devices advertising the "_bose-passport._tcp.local." service.

        This method initializes the devices list, creates a ServiceBrowser to listen for
        service events, waits for a given timeout period, and then closes the Zeroconf instance.

        Args:
            timeout (int): Time in seconds to wait for service discovery. Defaults to 5.

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each containing the keys "GUID" and "IP"
            for a discovered device.
        """
        self.devices = []

        # Create a ServiceBrowser that listens for service events and calls _on_service_state_change.
        listener = ServiceBrowser(self.zeroconf, "_bose-passport._tcp.local.", handlers=[self._on_service_state_change])

        try:
            time.sleep(timeout)
        finally:
            self.zeroconf.close()

        return self.devices