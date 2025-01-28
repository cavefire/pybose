"""
Bose Speaker control using its Websocket (like the BOSE app)

In order to control the device locally, you need to obtain the control token and device ID.
The control token needs to be aquired from the online BOSE API. The script "BoseAuth.py" can be used to obtain the control token using the email and password of the BOSE account.
The device ID can be obtained by discovering the device on the local network using the script "BoseDiscovery.py".

The token is only valid for a certain amount of time AND does not renew automatically.
So you may need to refetch the token from time to time.
"""

import json
import asyncio
import logging
from ssl import SSLContext, CERT_NONE
import websockets
from threading import Event
import BoseResponse as BoseResponse
import sys


class BoseSpeaker:
    def __init__(self, control_token: str, device_id: str, host: str, version = 1):
        self._control_token = control_token
        self._device_id = device_id
        self._host = host
        self._version = version
        self._websocket = None
        self._ssl_context = SSLContext()
        self._ssl_context.verify_mode = CERT_NONE
        self._subprotocol = "eco2"
        self._req_id = 1
        self._url = f"wss://{self._host}:8082/?product=Madrid-iOS:31019F02-F01F-4E73-B495-B96D33AD3664"
        self._responses = []
        self._stop_event = Event()
        self._receiver_task = None
        self._receivers = {}

    async def connect(self):
        """Connect to the WebSocket and start the receiver task."""
        self._websocket = await websockets.connect(
            self._url,
            subprotocols=[self._subprotocol],
            ssl=self._ssl_context
        )
        logging.info("WebSocket connection established.")

        self._stop_event.clear()
        self._receiver_task = asyncio.create_task(self._receiver_loop())

    async def disconnect(self):
        """Stop the receiver task and close the WebSocket."""
        self._stop_event.set()
        if self._receiver_task:
            await self._receiver_task
        if self._websocket:
            await self._websocket.close()
        logging.info("WebSocket connection closed.")

    def attach_receiver(self, callback) -> int:
        """Attach to receiver."""
        id = max(self._receivers.keys(), default=0) + 1
        self._receivers[id] = callback
        return id
    
    def detach_receiver(self, id):
        """Detach from receiver."""
        self.receivers.pop(id, None)

    async def _request(self, resource, method, body={}, withHeaders=False, waitForResponse=True):
        """Send a request and wait for the matching response."""
        token = self._control_token
        req_id = self._req_id
        self._req_id += 1

        message = {
            "body": body,
            "header": {
                "token": token,
                "version": self._version,
                "reqID": req_id,
                "resource": resource,
                "device": self._device_id,
                "msgtype": "REQUEST",
                "method": method
            }
        }

        await self._websocket.send(json.dumps(message))
        logging.debug(f"Sent message: {json.dumps(message, indent=4)}")

        # Wait for response with matching reqID
        if not waitForResponse:
            return
          
        # TODO: Refactor from polling to event-driven
        while True:
            for response in self._responses:
                if response["header"]["reqID"] == req_id:
                    self._responses.remove(response)
                    if not withHeaders:
                      return response["body"]
                    return response
            await asyncio.sleep(0.1)

    async def _receiver_loop(self):
        """Async function to receive and process messages."""
        try:
            while not self._stop_event.is_set():
                message = await self._websocket.recv()
                logging.debug(f"Received message: {message}")
                parsed_message = json.loads(message)

                # Check if the message is a response to a request
                if "header" in parsed_message and "reqID" in parsed_message["header"]:
                    self._responses.append(parsed_message)
                else:
                    # Notify all receivers about the unsolicited message
                    for receiver in self._receivers.values():
                        receiver(parsed_message)
        except Exception as e:
            if not self._stop_event.is_set():
                logging.error(f"Error in receiver loop: {e}")

    async def get_system_info(self) -> BoseResponse.SystemInfo:
        """Get system info."""
        return BoseResponse.SystemInfo(await self._request("/system/info", "GET"))

    async def get_audio_volume(self) -> BoseResponse.AudioVolume:
        """Get the current audio volume."""
        return BoseResponse.AudioVolume(await self._request("/audio/volume", "GET"))

    async def set_audio_volume(self, volume) -> BoseResponse.AudioVolume:
        """Set the audio volume."""
        body = {"value": volume}
        return BoseResponse.AudioVolume(await self._request("/audio/volume", "PUT", body))

    async def get_now_playing(self) -> BoseResponse.ContentNowPlaying:
        """Get the current playing content."""
        return BoseResponse.ContentNowPlaying(await self._request("/content/nowPlaying", "GET"))

    async def get_bluetooth_status(self):
        """Get the Bluetooth status."""
        return await self._request("/bluetooth/source/status", "GET")

    async def get_power_state(self) -> BoseResponse.SystemPowerControl:
        """Get the power state of the device."""
        return await self._request("/system/power/control", "GET")

    async def set_power_state(self, state: bool) -> None:
        """Set the power state of the device."""
        body = {"power": "ON" if state else "OFF"}
        await self._request("/system/power/control", "POST", body)

    async def _control_transport(self, control: str) -> BoseResponse.ContentNowPlaying:
        """Control the transport."""
        body = {"control": control}
        return BoseResponse.ContentNowPlaying(await self._request("/content/transportControl", "POST", body))

    async def pause(self) -> BoseResponse.ContentNowPlaying:
        """Pause the current content."""
        return await self._control_transport("PAUSE")
      
    async def play(self) -> BoseResponse.ContentNowPlaying:
        """Play the current content."""
        return await self._control_transport("PLAY")
      
    async def skip_next(self) -> BoseResponse.ContentNowPlaying:
        """Skip to the next content."""
        return await self._control_transport("SKIP_NEXT")
      
    async def skip_previous(self) -> BoseResponse.ContentNowPlaying:
        """Skip to the previous content."""
        return await self._control_transport("SKIP_PREVIOUS")

# EXAMPLE USAGE

async def main(control_token, device_id, host):
    bose = BoseSpeaker(
        control_token=control_token,
        device_id=device_id,
        host=host
    )
    
    # Attach receiver for unsolicited messages
    bose.attach_receiver(lambda data: print(f"Received unsolicited message: {json.dumps(data, indent=4)}"))
    
    # Connect to the speaker
    await bose.connect()
    
    # Get system info
    response = await bose.get_system_info()
    print(response)
    
    # Get audio volume
    response = await bose.get_audio_volume()
    print(response)
    
    # Set get currently playing content
    response = await bose.get_now_playing()
    print(response)
    
    # Safely disconnect from the speaker
    await bose.disconnect()
    
if __name__ == "__main__":  
    if len(sys.argv) != 4:
        print("Usage: python {sys.argv[0]} <control_token> <device_id> <host>")
        sys.exit(1)
    
    control_token = sys.argv[1]
    device_id = sys.argv[2]
    host = sys.argv[3]
  
    asyncio.run(main(control_token, device_id, host))