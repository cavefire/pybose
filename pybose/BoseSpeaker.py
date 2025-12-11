"""
Bose Speaker control using its WebSocket (like the BOSE app)

In order to control the device locally, you need to obtain the control token and device ID.
The control token is acquired from the online BOSE API (using BoseAuth.py), while the device ID
is obtained by discovering the device on the local network (using BoseDiscovery.py).

Note: The token is only valid for a limited time and does not renew automatically.
You may need to refetch the token periodically.
"""

from __future__ import annotations
import json
import asyncio
import logging
from ssl import SSLContext, CERT_NONE, PROTOCOL_TLS_CLIENT
import websockets
from threading import Event
from typing import Any, Callable, Dict, List, Optional, Union
from pybose.BoseAuth import BoseAuth

from . import BoseResponse as BR

# Default resources subscribed when connecting (same as in the BOSE app)
DEFAULT_SUBSCRIBE_RESOURCES: List[str] = [
    "/bluetooth/sink/list",
    "/system/power/control",
    "/audio/avSync",
    "/bluetooth/source/list",
    "/audio/bass",
    "/device/assumed/TVs",
    "/network/wifi/siteScan",
    "/system/update/start",
    "/system/update/status",
    "/bluetooth/sink/macAddr",
    "/content/nowPlaying/rating",
    "/bluetooth/source/stopScan",
    "/system/setup",
    "/homekit/info",
    "/bluetooth/source/pairStatus",
    "/device/configuredDevices",
    "/bluetooth/source/status",
    "/cast/teardown",
    "/bluetooth/sink/status",
    "/cast/setup",
    "/cec",
    "/cloudSync",
    "/system/challenge",
    "/bluetooth/sink/remove",
    "/bluetooth/source/connect",
    "/remote/integration/brandList",
    "/subscription",
    "/network/status",
    "/bluetooth/source/scanResult",
    "/content/playbackRequest",
    "/audio/eqSelect",
    "/audio/height",
    "/content/transportControl",
    "/grouping/activeGroups",
    "/audio/mode",
    "/bluetooth/source/pair",
    "/bluetooth/source/capability",
    "/bluetooth/source/disconnect",
    "/audio/subwooferGain",
    "/voice/setup/start",
    "/audio/center",
    "/network/wifi/status",
    "/content/nowPlaying/repeat",
    "/system/sources",
    "/content/nowPlaying",
    "/system/power/macro",
    "/bluetooth/sink/pairable",
    "/network/wifi/profile",
    "/cast/settings",
    "/audio/zone",
    "/content/nowPlaying/shuffle",
    "/bluetooth/source/capabilitySettings",
    "/remote/integration",
    "/audio/surround",
    "/accessories",
    "/audio/treble",
    "/adaptiq",
    "/accessories/playTones",
    "/system/power/timeouts",
    "/audio/dualMonoSelect",
    "/system/info",
    "/system/sources/status",
    "/audio/rebroadcastLatency/mode",
    "/audio/format",
    "/bluetooth/source/connectionStatus",
    "/system/power/mode/opticalAutoWake",
    "/content/nowPlaying/favorite",
    "/system/productSettings",
    "/bluetooth/sink/connectionStatus",
    "/bluetooth/source/remove",
    "/audio/autoVolume",
    "/system/capabilities",
    "/audio/volume/increment",
    "/bluetooth/sink/connect",
    "/bluetooth/source/volume",
    "/bluetooth/sink/disconnect",
    "/system/reset",
    "/audio/volume/decrement",
    "/audio/volume",
    "/remote/integration/directEntry",
    "/device/configure",
    "/device/setup",
    "/bluetooth/source/scan",
    "/voice/settings",
    "/system/activated",
]


class BoseSpeaker:
    def __init__(
        self,
        host: str,
        device_id: Optional[str] = None,
        version: int = 1,
        auto_reconnect: bool = True,
        bose_auth: BoseAuth = None,
        on_exception: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        self._device_id: Optional[str] = device_id
        self._host: str = host
        self._version: int = version
        self._websocket: Optional[websockets.connect] = None
        self._ssl_context: SSLContext = SSLContext(PROTOCOL_TLS_CLIENT)
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = CERT_NONE
        self._subprotocol: str = "eco2"
        self._req_id: int = 1
        self._url: str = f"wss://{self._host}:8082/?product=Madrid-iOS:31019F02-F01F-4E73-B495-B96D33AD3664"
        self._responses: List[BR.BoseMessage] = []
        self._stop_event: Event = Event()
        self._receiver_task: Optional[asyncio.Task] = None
        self._receivers: Dict[int, Callable[[BR.BoseMessage], None]] = {}
        self._subscribed_resources: List[str] = []
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._capabilities: Optional[BR.Capabilities] = None
        self._auto_reconnect = auto_reconnect
        self._bose_auth: BoseAuth = bose_auth
        self._on_exception = on_exception
        self._connected = False

    async def connect(self) -> None:
        """Connect to the WebSocket and start the receiver loop."""
        await self.disconnect()
        self._websocket = await websockets.connect(
            self._url, subprotocols=[self._subprotocol], ssl=self._ssl_context
        )
        logging.info("WebSocket connection established.")
        self._stop_event.clear()
        self._receiver_task = asyncio.create_task(self._receiver_loop())
        if self._subscribed_resources:
            logging.debug("Subscribing to resources from previous session.")
            await self.subscribe(self._subscribed_resources)
        await self.get_capabilities()
        self._connected = True

    async def disconnect(self) -> None:
        """Stop the receiver loop and close the WebSocket connection."""
        self._stop_event.set()
        current_task = asyncio.current_task()
        if self._receiver_task and self._receiver_task != current_task:
            await self._receiver_task
        if self._websocket:
            await self._websocket.close()
        logging.info("WebSocket connection closed.")
        self._connected = False

    def attach_receiver(self, callback: Callable[[BR.BoseMessage], None]) -> int:
        """Attach a callback to receive unsolicited messages."""
        receiver_id = max(self._receivers.keys(), default=0) + 1
        self._receivers[receiver_id] = callback
        return receiver_id

    def detach_receiver(self, receiver_id: int) -> None:
        """Detach a previously attached receiver."""
        self._receivers.pop(receiver_id, None)

    async def _request(
        self,
        resource: str,
        method: str,
        body: Optional[Dict[str, Any]] = None,
        withHeaders: bool = False,
        waitForResponse: bool = True,
        version: Optional[int] = None,
        checkCapabilities: bool = True,
    ) -> Dict[str, Any]:
        """Send a request over the WebSocket and wait for the matching response."""
        if body is None:
            body = {}

        token: str = self._bose_auth.getCachedToken().get("access_token")
        req_id: int = self._req_id
        self._req_id += 1

        version = version if version is not None else self._version

        if checkCapabilities and not self.has_capability(resource):
            ex = BoseFunctionNotSupportedException(
                f"Resource {resource} is not supported by the device."
            )
            if self._on_exception:
                self._on_exception(ex)
            raise ex

        header: BR.BoseHeader = {
            "device": self._device_id,
            "method": method,
            "msgtype": "REQUEST",
            "reqID": req_id,
            "resource": resource,
            "status": 200,
            "token": token,
            "version": version,
        }
        message: BR.BoseMessage = {"body": body, "header": header}

        if self._device_id is None:
            await self._message_queue.put(message)
            logging.debug(
                f"Waiting for deviceID. Queued message: {json.dumps(message, indent=4)}"
            )
        else:
            try:
                await self._websocket.send(json.dumps(message))
            except websockets.ConnectionClosed:
                self._connected = False
                if self._auto_reconnect:
                    logging.warning(
                        "WebSocket connection is closed. Reconnecting before sending message."
                    )
                    await self.connect()
                    await self._websocket.send(json.dumps(message))
                else:
                    logging.error(
                        "WebSocket connection is closed. Cannot send message."
                    )
                    ex = Exception(
                        "WebSocket connection is closed. Cannot send message."
                    )
                    if self._on_exception:
                        self._on_exception(ex)
                    raise ex

            logging.debug(f"Sent message: {json.dumps(message, indent=4)}")

        if not waitForResponse:
            return {}

        while True:
            for response in self._responses:
                resp_header = response.get("header", {})
                if (
                    resp_header.get("msgtype") == BR.BoseHeaderMsgTypeEnum.RESPONSE
                    and resp_header.get("reqID") == req_id
                ):
                    self._responses.remove(response)
                    status = resp_header.get("status")
                    if status is None:
                        ex = BoseRequestException(
                            method,
                            resource,
                            body,
                            999,
                            999,
                            f"pybose could not parse the message: {response}",
                        )
                        if self._on_exception:
                            self._on_exception(ex)
                        raise ex
                    if status != 200:
                        error = response.get(
                            "error",
                            {
                                "status": 999,
                                "message": f"pybose could not determine the error, but status code is {status}",
                            },
                        )
                        ex = BoseRequestException(
                            method,
                            resource,
                            body,
                            status,
                            error["code"],
                            error["message"],
                        )
                        if self._on_exception:
                            self._on_exception(ex)
                        raise ex
                    return response["body"] if not withHeaders else response
            await asyncio.sleep(0.1)

    async def _receiver_loop(self) -> None:
        """Continuously receive and process messages from the WebSocket."""
        try:
            while not self._stop_event.is_set():
                message = await self._websocket.recv()
                self._connected = True
                logging.debug(f"Received message: {message}")
                parsed_message: BR.BoseMessage = json.loads(message)
                header: BR.BoseHeader = parsed_message.get("header", {})
                if header.get("device") is not None and self._device_id is None:
                    self._device_id = header["device"]
                    logging.debug(
                        f"Received first message from device. Device ID: {self._device_id}"
                    )
                    logging.debug(
                        f"Sending {self._message_queue.qsize()} queued messages."
                    )
                    while not self._message_queue.empty():
                        queued_msg = await self._message_queue.get()
                        queued_msg["header"]["device"] = self._device_id
                        await self._websocket.send(json.dumps(queued_msg))
                if (
                    header.get("msgtype") == BR.BoseHeaderMsgTypeEnum.RESPONSE
                    and header.get("reqID") is not None
                ):
                    logging.debug(f"Response received for reqID: {header['reqID']}")
                    self._responses.append(parsed_message)
                else:
                    for receiver in self._receivers.values():
                        receiver(parsed_message)
        except websockets.ConnectionClosed:
            logging.warning("WebSocket connection lost.")
            if self._auto_reconnect:
                logging.info("Reconnecting...")
                asyncio.create_task(self.connect())
            else:
                logging.error("WebSocket connection closed.")
        except Exception as e:
            if not self._stop_event.is_set():
                logging.error(f"Error in receiver loop: {e}")

    async def get_capabilities(self) -> BR.Capabilities:
        """Retrieve the device capabilities."""
        self._capabilities = BR.Capabilities(
            await self._request("/system/capabilities", "GET", checkCapabilities=False)
        )
        return self._capabilities

    def has_capability(self, endpoint: str) -> bool:
        """Return True if the device has the specified capability."""
        if self._capabilities is None:
            ex = BoseCapabilitiesNotLoadedException()
            if self._on_exception:
                self._on_exception(ex)
            raise ex
        groups: List[BR.CapabilityGroup] = self._capabilities.get("group", [])
        endpoints: List[str] = [
            ep.get("endpoint") for group in groups for ep in group.get("endpoints", [])
        ]
        return endpoint in endpoints

    async def get_system_info(self) -> BR.SystemInfo:
        """Retrieve system information."""
        return BR.SystemInfo(await self._request("/system/info", "GET"))

    async def get_audio_volume(self) -> BR.AudioVolume:
        """Retrieve the current audio volume."""
        return BR.AudioVolume(await self._request("/audio/volume", "GET"))

    async def set_audio_volume(self, volume: int) -> BR.AudioVolume:
        """Set the audio volume to the specified value."""
        body = {"value": volume}
        return BR.AudioVolume(await self._request("/audio/volume", "PUT", body))

    async def set_audio_volume_muted(self, muted: bool) -> BR.AudioVolume:
        """Set the audio volume muted state."""
        body = {"muted": muted}
        return BR.AudioVolume(await self._request("/audio/volume", "PUT", body))

    async def get_now_playing(self) -> BR.ContentNowPlaying:
        """Retrieve the currently playing content."""
        return BR.ContentNowPlaying(await self._request("/content/nowPlaying", "GET"))

    async def get_bluetooth_source_status(self) -> BR.BluetoothSourceStatus:
        """Retrieve Bluetooth source status."""
        return await self._request("/bluetooth/source/status", "GET")  # type: ignore

    async def get_bluetooth_sink_status(self) -> BR.BluetoothSinkStatus:
        """Retrieve Bluetooth sink status."""
        return await self._request("/bluetooth/sink/status", "GET")  # type: ignore

    async def get_bluetooth_sink_list(self) -> BR.BluetoothSinkList:
        """Retrieve list of Bluetooth sink devices."""
        return await self._request("/bluetooth/sink/list", "GET")  # type: ignore

    async def set_bluetooth_sink_pairable(self) -> None:
        """Make the device pairable for Bluetooth connections."""
        await self._request("/bluetooth/sink/pairable", "POST", withHeaders=True)

    async def connect_bluetooth_sink_device(self, mac_address: str) -> None:
        """Connect to a specific Bluetooth sink device by MAC address."""
        body = {"mac": mac_address}
        await self._request("/bluetooth/sink/connect", "POST", body, withHeaders=True)

    async def disconnect_bluetooth_sink_device(self, mac_address: str) -> None:
        """Disconnect from a specific Bluetooth sink device by MAC address."""
        body = {"mac": mac_address}
        await self._request(
            "/bluetooth/sink/disconnect", "POST", body, withHeaders=True
        )

    async def remove_bluetooth_sink_device(self, mac_address: str) -> None:
        """Remove (unpair) a specific Bluetooth sink device by MAC address."""
        body = {"mac": mac_address}
        await self._request("/bluetooth/sink/remove", "POST", body, withHeaders=True)

    async def get_power_state(self) -> BR.SystemPowerControl:
        """Retrieve the power state of the device."""
        return await self._request("/system/power/control", "GET")

    async def set_power_state(self, state: bool) -> None:
        """Set the device power state."""
        body = {"power": "ON" if state else "OFF"}
        await self._request("/system/power/control", "POST", body)

    async def _control_transport(self, control: str) -> BR.ContentNowPlaying:
        """Send a transport control command."""
        body = {"state": control}
        return BR.ContentNowPlaying(
            await self._request("/content/transportControl", "PUT", body)
        )

    async def pause(self) -> BR.ContentNowPlaying:
        """Pause playback."""
        return await self._control_transport("PAUSE")

    async def play(self) -> BR.ContentNowPlaying:
        """Resume playback."""
        return await self._control_transport("PLAY")

    async def skip_next(self) -> BR.ContentNowPlaying:
        """Skip to the next item."""
        return await self._control_transport("SKIPNEXT")

    async def skip_previous(self) -> BR.ContentNowPlaying:
        """Skip to the previous item."""
        return await self._control_transport("SKIPPREVIOUS")

    async def seek(self, position: Union[float, int]) -> BR.ContentNowPlaying:
        """Seek to a specified position (in seconds)."""
        body = {"position": position, "state": "SEEK"}
        return await self._request("/content/transportControl", "PUT", body)

    async def request_playback_preset(
        self, preset: BR.Preset, initiator_id: str
    ) -> bool:
        """Request a playback preset."""
        content_item = preset["actions"][0]["payload"]["contentItem"]
        body = {
            "source": content_item.get("source"),
            "initiatorID": initiator_id,
            "sourceAccount": content_item.get("sourceAccount"),
            "preset": {
                "location": content_item.get("location"),
                "name": content_item.get("name"),
                "containerArt": content_item.get("containerArt"),
                "presetable": content_item.get("presetable"),
                "type": content_item.get("type"),
            },
        }
        return await self._request("/content/playbackRequest", "POST", body)

    def get_device_id(self) -> Optional[str]:
        """Return the device ID (if available)."""
        return self._device_id

    async def subscribe(
        self, resources: List[str] = DEFAULT_SUBSCRIBE_RESOURCES
    ) -> dict:
        """Subscribe to a list of resources."""
        body = {
            "notifications": [
                {"resource": resource, "version": 1} for resource in resources
            ]
        }
        self._subscribed_resources = resources
        return await self._request("/subscription", "PUT", body, version=2)

    async def switch_tv_source(self) -> BR.ContentNowPlaying:
        """Switch the speaker’s source to TV."""
        return await self.set_source("PRODUCT", "TV")

    async def set_source(self, source: str, sourceAccount: str) -> BR.ContentNowPlaying:
        """Set the playback source."""
        body = {"source": source, "sourceAccount": sourceAccount}
        return BR.ContentNowPlaying(
            await self._request("/content/playbackRequest", "POST", body)
        )

    async def get_sources(self) -> BR.Sources:
        """Retrieve available sources."""
        return BR.Sources(await self._request("/system/sources", "GET"))

    async def get_audio_setting(self, option: str) -> BR.Audio:
        """Retrieve an audio setting value."""
        if option not in [
            "bass",
            "treble",
            "center",
            "subwooferGain",
            "surround",
            "height",
            "avSync",
        ]:
            ex = BoseInvalidAudioSettingException(option)
            if self._on_exception:
                self._on_exception(ex)
            raise ex
        return BR.Audio(await self._request("/audio/" + option, "GET"))

    async def set_audio_setting(self, option: str, value: int) -> BR.Audio:
        """Set an audio setting value."""
        if option not in [
            "bass",
            "treble",
            "center",
            "subwooferGain",
            "surround",
            "height",
            "avSync",
        ]:
            ex = BoseInvalidAudioSettingException(option)
            if self._on_exception:
                self._on_exception(ex)
            raise ex
        return BR.Audio(
            await self._request("/audio/" + option, "POST", {"value": value})
        )

    async def get_accessories(self) -> BR.Accessories:
        """Retrieve accessories information."""
        return BR.Accessories(await self._request("/accessories", "GET"))

    async def put_accessories(
        self, subs_enabled: Optional[bool] = None, rears_enabled: Optional[bool] = None
    ) -> bool:
        """Update accessories settings."""
        if subs_enabled is None and rears_enabled is None:
            accessories = await self.get_accessories()
            subs_enabled = accessories.enabled.subs  # type: ignore
            rears_enabled = accessories.enabled.rears  # type: ignore
        body = {"enabled": {"rears": rears_enabled, "subs": subs_enabled}}
        return await self._request("/accessories", "PUT", body)

    async def get_battery_status(self) -> BR.Battery:
        """Retrieve battery status."""
        return BR.Battery(await self._request("/system/battery", "GET"))

    async def get_audio_mode(self) -> BR.AudioMode:
        """Retrieve the audio mode."""
        return BR.AudioMode(await self._request("/audio/mode", "GET"))

    async def set_audio_mode(self, mode: str) -> bool:
        """Set the audio mode."""
        result = await self._request("/audio/mode", "POST", {"value": mode})
        return result.get("value") == mode

    async def get_dual_mono_setting(self) -> BR.DualMonoSettings:
        """Retrieve the dual mono setting."""
        return BR.DualMonoSettings(await self._request("/audio/dualMonoSelect", "GET"))

    async def set_dual_mono_setting(self, value: Union[int, str]) -> bool:
        """Set the dual mono setting."""
        result = await self._request("/audio/dualMonoSelect", "POST", {"value": value})
        return result.get("value") == value

    async def get_rebroadcast_latency_mode(self) -> BR.RebroadcastLatencyMode:
        """Retrieve the rebroadcast latency mode."""
        return await self._request("/audio/rebroadcastLatency/mode", "GET")

    async def set_rebroadcast_latency_mode(self, mode: str) -> bool:
        """Set the rebroadcast latency mode."""
        result = await self._request(
            "/audio/rebroadcastLatency/mode", "PUT", {"mode": mode}
        )
        return result.get("value") == mode

    async def get_active_groups(self) -> List[BR.ActiveGroup]:
        """Retrieve active groups."""
        groups = await self._request("/grouping/activeGroups", "GET")
        return [BR.ActiveGroup(group) for group in groups.get("activeGroups", [])]

    async def set_active_group(self, other_product_ids: List[str]) -> bool:
        """Set the active group including this device and other products."""
        body = {"products": [{"productId": self._device_id, "role": "NORMAL"}]}
        for product_id in other_product_ids:
            body["products"].append({"productId": product_id, "role": "NORMAL"})
        return await self._request("/grouping/activeGroups", "POST", body)

    async def add_to_active_group(
        self, active_group_id: str, other_product_ids: List[str]
    ) -> bool:
        """Add products to the active group."""
        body = {
            "activeGroupId": active_group_id,
            "addProducts": [
                {"productId": pid, "role": "NORMAL"} for pid in other_product_ids
            ],
            "addGroups": [],
            "removeGroups": [],
            "removeProducts": [],
        }
        return await self._request("/grouping/activeGroups", "PUT", body)

    async def remove_from_active_group(
        self, active_group_id: str, other_product_ids: List[str]
    ) -> bool:
        """Remove products from the active group."""
        body = {
            "name": "",
            "activeGroupId": active_group_id,
            "addProducts": [],
            "addGroups": [],
            "removeGroups": [],
            "removeProducts": [
                {"productId": pid, "role": "NORMAL"} for pid in other_product_ids
            ],
        }
        return await self._request("/grouping/activeGroups", "PUT", body)

    async def stop_active_groups(self) -> bool:
        """Stop all active groups."""
        return await self._request("/grouping/activeGroups", "DELETE")

    async def get_system_timeout(self) -> BR.SystemTimeout:
        """Retrieve the system timeout settings."""
        return BR.SystemTimeout(await self._request("/system/power/timeouts", "GET"))

    async def set_system_timeout(
        self, no_audio: bool, no_video: bool
    ) -> BR.SystemTimeout:
        """Set system timeout settings."""
        body = {"noAudio": no_audio, "noVideo": no_video}
        return BR.SystemTimeout(
            await self._request("/system/power/timeouts", "PUT", body)
        )

    async def get_cec_settings(self) -> BR.CecSettings:
        """Retrieve the CEC settings."""
        return BR.CecSettings(await self._request("/cec", "GET"))

    async def set_cec_settings(
        self, mode: BR.CecSettingsSupportedValuesEnum
    ) -> BR.CecSettings:
        """Set the CEC settings."""
        return BR.CecSettings(await self._request("/cec", "PUT", {"mode": mode}))

    async def get_product_settings(self) -> BR.ProductSettings:
        """Retrieve the product settings."""
        return BR.ProductSettings(await self._request("/system/productSettings", "GET"))

    async def get_network_status(self) -> BR.NetworkStatus:
        """Retrieve the network status."""
        return BR.NetworkStatus(await self._request("/network/status", "GET"))

    def is_connected(self) -> bool:
        """Return True if the WebSocket is connected."""
        return self._connected

    async def set_chromecast(self, enable: bool = True) -> Dict[str, Any]:
        """Enable Chromecast on the device (PUT /cast/setup)."""
        body: Dict[str, Any] = {
            "bosePersonID": self._bose_auth.getControlToken().get("bosePersonID")
        }
        return await self._request(
            "/cast/setup" if enable else "/cast/teardown", "PUT", body
        )


class BoseFunctionNotSupportedException(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class BoseCapabilitiesNotLoadedException(Exception):
    def __init__(self) -> None:
        self.message = "Capabilities not loaded yet."
        super().__init__(self.message)


class BoseInvalidAudioSettingException(Exception):
    def __init__(self, setting: str) -> None:
        self.setting = setting
        self.message = f"Invalid audio setting: {setting}"
        super().__init__(self.message)


class BoseRequestException(Exception):
    def __init__(
        self,
        method: str,
        resource: str,
        body: Dict[str, Any],
        http_status: int,
        error_status: int,
        message: str,
    ) -> None:
        self.method = method
        self.resource = resource
        self.body = body
        self.http_status = http_status
        self.error_status = error_status
        self.message = message

        super().__init__(
            f"'{method} {resource}' returned {http_status}: Bose Error #{error_status} - {self.message}"
        )
        logging.debug(f"Request body for previous error: {json.dumps(body, indent=4)}")
