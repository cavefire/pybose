import asyncio
import json
import pytest
from ssl import CERT_NONE
from unittest.mock import patch

from pybose.BoseSpeaker import (
    BoseSpeaker,
    BoseAuth,
    BoseInvalidAudioSettingException,
    BoseRequestException,
)

# Helper async function (optional)
async def async_return(result):
    return result

# Dummy async fake connect to avoid real network connection
async def fake_connect(url, subprotocols, ssl):
    class FakeWS:
        def __init__(self):
            self.closed = False
            self.close_code = None
        async def send(self, message):
            pass
        async def recv(self):
            await asyncio.sleep(0.05)
            return json.dumps({
                "header": {"msgtype": "RESPONSE", "reqID": 1, "status": 200},
                "body": {"dummy": "capabilities", "device": "new-device-id"}
            })
        async def close(self):
            self.closed = True
            self.close_code = 1000
    return FakeWS()

# --- Synchronous methods ---

def test_bose_speaker_init():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    assert bose.get_device_id() == "dummy_device"
    assert bose._host == "dummy_host"
    # Assuming _req_id starts at 1
    assert bose._req_id == 1
    # Check that the SSL context is created with verification disabled
    assert bose._ssl_context.verify_mode == CERT_NONE
    # Other internal variables
    assert bose._subprotocol == "eco2"
    assert isinstance(bose._responses, list)
    assert isinstance(bose._receivers, dict)

def test_attach_and_detach_receiver():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host")
    callback = lambda msg: None
    rec_id = bose.attach_receiver(callback)
    assert rec_id in bose._receivers
    bose.detach_receiver(rec_id)
    assert rec_id not in bose._receivers

@pytest.mark.asyncio
async def test_request_success():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    bose._req_id = 1
    # Patch has_capability to always return True
    bose.has_capability = lambda endpoint: True

    # Use the FakeWebsocket class (which defines a send method) for fake_connect.
    async def fake_connect():
        bose._websocket = FakeWebsocket()
    await fake_connect()

    dummy_response = {
        "header": {
            "msgtype": "RESPONSE",
            "reqID": 1,
            "status": 200,
        },
        "body": {"result": "success"},
    }
    bose._responses.append(dummy_response)
    result = await bose._request("/dummy/resource", "GET")
    assert result == {"result": "success"}


@pytest.mark.asyncio
async def test_request_error():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    bose._req_id = 1
    bose.has_capability = lambda endpoint: True

    async def fake_connect():
        bose._websocket = FakeWebsocket()
    bose.connect = fake_connect
    await bose.connect()
    await bose.connect()

    dummy_response = {
        "header": {
            "msgtype": "RESPONSE",
            "reqID": 1,
            "status": 400,
        },
        "error": {"code": 123, "message": "Error occurred"},
    }
    bose._responses.append(dummy_response)
    with pytest.raises(BoseRequestException) as excinfo:
        await bose._request("/dummy/resource", "GET")
    assert "400" in str(excinfo.value)
    
    
# --- Testing connection and disconnection ---
class FakeWebsocket:
    def __init__(self):
        self.closed = False
        self.close_code = None
    async def send(self, message):
        pass
    async def recv(self):
        await asyncio.sleep(0.05)
        return json.dumps({
            "header": {"msgtype": "RESPONSE", "reqID": 1, "status": 200},
            "body": {"dummy": "capabilities", "device": "new-device-id"}
        })
    async def close(self):
        self.closed = True
        self.close_code = 1000

@pytest.mark.asyncio
async def test_connect_and_disconnect():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    # Override connect to not actually call websockets.connect
    bose.connect = lambda: asyncio.sleep(0)
    bose._websocket = FakeWebsocket()
    bose.get_capabilities = lambda: asyncio.sleep(0)
    await bose.connect()
    assert bose._websocket is not None
    await bose.disconnect()
    assert bose._websocket.close_code == 1000

# --- Testing wrapper functions that delegate to _request ---
@pytest.mark.asyncio
async def test_get_capabilities():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_capabilities = {"group": []}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_capabilities
    bose._request = fake_request
    caps = await bose.get_capabilities()
    assert caps == dummy_capabilities
    assert bose._capabilities == dummy_capabilities

@pytest.mark.asyncio
async def test_get_system_info():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_info = {"system": "info"}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_info
    bose._request = fake_request
    result = await bose.get_system_info()
    assert result == dummy_info

@pytest.mark.asyncio
async def test_get_audio_volume():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_volume = {"volume": 50}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_volume
    bose._request = fake_request
    result = await bose.get_audio_volume()
    assert result == dummy_volume

@pytest.mark.asyncio
async def test_set_audio_volume():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    volume = 75
    captured_body = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return {"volume": volume}
    bose._request = fake_request
    result = await bose.set_audio_volume(volume)
    assert result == {"volume": volume}
    assert captured_body == {"value": volume}

@pytest.mark.asyncio
async def test_get_now_playing():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_now_playing = {"nowPlaying": "song"}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_now_playing
    bose._request = fake_request
    result = await bose.get_now_playing()
    assert result == dummy_now_playing

@pytest.mark.asyncio
async def test_get_power_state_and_set_power_state():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_power = {"power": "ON"}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_power
    bose._request = fake_request
    state = await bose.get_power_state()
    assert state == dummy_power

    captured_body = None
    async def fake_set_request(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return {}
    bose._request = fake_set_request
    await bose.set_power_state(True)
    assert captured_body == {"power": "ON"}
    await bose.set_power_state(False)
    assert captured_body == {"power": "OFF"}

# --- Testing transport control functions (pause, play, skip, seek) ---
@pytest.mark.asyncio
async def test_control_transport_functions():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    async def fake_control_transport(control):
        return {"state": control}
    bose._control_transport = fake_control_transport

    result = await bose.pause()
    assert result["state"] == "PAUSE"

    result = await bose.play()
    assert result["state"] == "PLAY"

    result = await bose.skip_next()
    assert result["state"] == "SKIPNEXT"

    result = await bose.skip_previous()
    assert result["state"] == "SKIPPREVIOUS"

    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return body
    bose._request = fake_request
    position = 120
    result = await bose.seek(position)
    assert result == {"position": position, "state": "SEEK"}

# --- Testing request_playback_preset ---
@pytest.mark.asyncio
async def test_request_playback_preset():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_preset = {
        "actions": [
            {"payload": {"contentItem": {
                "source": "dummy_source",
                "sourceAccount": "dummy_account",
                "location": "dummy_location",
                "name": "dummy_name",
                "containerArt": "dummy_art",
                "presetable": True,
                "type": "dummy_type",
            }}}
        ]
    }
    async def fake_request(*args, **kwargs):
        return True
    bose._request = fake_request
    result = await bose.request_playback_preset(dummy_preset, "initiator123")
    assert result is True

# --- Testing subscribe and source functions ---
@pytest.mark.asyncio
async def test_subscribe():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_response = {"subscribed": True}
    captured_args = None
    async def fake_request(resource, method, body=None, version=None, **kwargs):
        nonlocal captured_args
        if body is None:
            body = {}
        captured_args = (resource, method, body, version)
        return dummy_response
    bose._request = fake_request
    result = await bose.subscribe(["/dummy/resource"])
    assert result == dummy_response
    assert bose._subscribed_resources == ["/dummy/resource"]

@pytest.mark.asyncio
async def test_switch_tv_source():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    async def fake_set_source(source, sourceAccount):
        return {"nowPlaying": "tv"}
    bose.set_source = fake_set_source
    result = await bose.switch_tv_source()
    assert result["nowPlaying"] == "tv"

@pytest.mark.asyncio
async def test_set_source():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return body
    bose._request = fake_request
    # Remove any override on set_source so that the actual method is used.
    if hasattr(bose, "set_source_original"):
        bose.set_source = bose.set_source_original
    else:
        # Force using _request implementation by deleting the attribute if it exists
        if "set_source" in bose.__dict__:
            del bose.__dict__["set_source"]
    result = await bose.set_source("PRODUCT", "TV")
    assert result == {"source": "PRODUCT", "sourceAccount": "TV"}

# --- Testing get_sources ---
@pytest.mark.asyncio
async def test_get_sources():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_sources = {"sources": ["source1", "source2"]}
    async def fake_request(*args, **kwargs):
        return dummy_sources
    bose._request = fake_request
    result = await bose.get_sources()
    assert result == dummy_sources

# --- Testing audio setting functions ---
@pytest.mark.asyncio
async def test_get_audio_setting_valid():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_audio = {"audio": "value"}
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_audio
    bose._request = fake_request
    result = await bose.get_audio_setting("bass")
    assert result == dummy_audio

@pytest.mark.asyncio
async def test_get_audio_setting_invalid():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    with pytest.raises(BoseInvalidAudioSettingException):
        await bose.get_audio_setting("invalid_option")

@pytest.mark.asyncio
async def test_set_audio_setting_valid():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    option = "treble"
    value = 10
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return body
    bose._request = fake_request
    result = await bose.set_audio_setting(option, value)
    assert result == {"value": int(value)}

# --- Testing accessories functions ---
@pytest.mark.asyncio
async def test_get_accessories():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_accessories = {"accessories": True}
    async def fake_request(*args, **kwargs):
        return dummy_accessories
    bose._request = fake_request
    result = await bose.get_accessories()
    assert result == dummy_accessories

@pytest.mark.asyncio
async def test_put_accessories():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    class DummyEnabled:
        subs = True
        rears = False
    class DummyAccessories:
        enabled = DummyEnabled()
    async def fake_get_accessories():
        return DummyAccessories()
    bose.get_accessories = fake_get_accessories
    captured_body = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return True
    bose._request = fake_request
    result = await bose.put_accessories()
    assert result is True
    assert captured_body == {"enabled": {"rears": False, "subs": True}}

# --- Testing battery, audio mode, dual mono, and latency mode functions ---
@pytest.mark.asyncio
async def test_get_battery_status():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_battery = {"battery": 80}
    async def fake_request(*args, **kwargs):
        return dummy_battery
    bose._request = fake_request
    result = await bose.get_battery_status()
    assert result == dummy_battery

@pytest.mark.asyncio
async def test_get_audio_mode_and_set_audio_mode():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_mode = {"mode": "stereo"}
    async def fake_request(*args, **kwargs):
        return dummy_mode
    bose._request = fake_request
    result = await bose.get_audio_mode()
    assert result == dummy_mode

    mode = "mono"
    async def fake_request_set(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": mode}
    bose._request = fake_request_set
    result = await bose.set_audio_mode(mode)
    assert result is True
    async def fake_request_fail(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": "different"}
    bose._request = fake_request_fail
    result = await bose.set_audio_mode(mode)
    assert result is False

@pytest.mark.asyncio
async def test_get_dual_mono_and_set_dual_mono_setting():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_dm = {"dualMono": "setting"}
    async def fake_request(*args, **kwargs):
        return dummy_dm
    bose._request = fake_request
    result = await bose.get_dual_mono_setting()
    assert result == dummy_dm

    value = "value1"
    async def fake_request_set(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": value}
    bose._request = fake_request_set
    result = await bose.set_dual_mono_setting(value)
    assert result is True
    async def fake_request_fail(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": "different"}
    bose._request = fake_request_fail
    result = await bose.set_dual_mono_setting(value)
    assert result is False

@pytest.mark.asyncio
async def test_get_rebroadcast_latency_mode_and_set_rebroadcast_latency_mode():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_mode = {"mode": "auto"}
    async def fake_request(*args, **kwargs):
        return dummy_mode
    bose._request = fake_request
    result = await bose.get_rebroadcast_latency_mode()
    assert result == dummy_mode

    mode = "manual"
    async def fake_request_set(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": mode}
    bose._request = fake_request_set
    result = await bose.set_rebroadcast_latency_mode(mode)
    assert result is True
    async def fake_request_fail(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"value": "different"}
    bose._request = fake_request_fail
    result = await bose.set_rebroadcast_latency_mode(mode)
    assert result is False

# --- Testing active groups functions ---
@pytest.mark.asyncio
async def test_get_active_groups():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="dummy_device")
    dummy_groups = {"activeGroups": [{"group": "group1"}, {"group": "group2"}]}
    async def fake_request(*args, **kwargs):
        return dummy_groups
    bose._request = fake_request
    result = await bose.get_active_groups()
    assert len(result) == 2

@pytest.mark.asyncio
async def test_set_active_group():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    captured_body = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return True
    bose._request = fake_request
    result = await bose.set_active_group(["device2", "device3"])
    assert result is True
    assert captured_body["products"][0]["productId"] == "device1"
    assert captured_body["products"][1]["productId"] == "device2"
    assert captured_body["products"][2]["productId"] == "device3"

@pytest.mark.asyncio
async def test_add_and_remove_from_active_group():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    captured_body = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return True
    bose._request = fake_request
    result = await bose.add_to_active_group("group1", ["device2", "device3"])
    assert result is True
    assert captured_body["activeGroupId"] == "group1"
    assert len(captured_body["addProducts"]) == 2

    captured_body = None
    result = await bose.remove_from_active_group("group1", ["device2"])
    assert result is True
    assert captured_body["activeGroupId"] == "group1"
    assert len(captured_body["removeProducts"]) == 1

@pytest.mark.asyncio
async def test_stop_active_groups():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    async def fake_request(*args, **kwargs):
        return True
    bose._request = fake_request
    result = await bose.stop_active_groups()
    assert result is True

# --- Testing system timeout functions ---
@pytest.mark.asyncio
async def test_get_and_set_system_timeout():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_timeout = {"timeout": 30}
    async def fake_request(*args, **kwargs):
        return dummy_timeout
    bose._request = fake_request
    result = await bose.get_system_timeout()
    assert result == dummy_timeout

    captured_body = None
    async def fake_request_set(resource, method, body=None, **kwargs):
        nonlocal captured_body
        if body is None:
            body = {}
        captured_body = body
        return dummy_timeout
    bose._request = fake_request_set
    result = await bose.set_system_timeout(True, False)
    assert result == dummy_timeout
    assert captured_body == {"noAudio": True, "noVideo": False}

# --- Testing CEC and product settings functions ---
@pytest.mark.asyncio
async def test_get_and_set_cec_settings():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_cec = {"cec": "settings"}
    async def fake_request(*args, **kwargs):
        return dummy_cec
    bose._request = fake_request
    result = await bose.get_cec_settings()
    assert result == dummy_cec

    mode = "mode1"
    async def fake_request_set(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return {"mode": mode}
    bose._request = fake_request_set
    result = await bose.set_cec_settings(mode)
    assert result["mode"] == mode

@pytest.mark.asyncio
async def test_get_product_settings():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_settings = {"setting": "value"}
    async def fake_request(*args, **kwargs):
        return dummy_settings
    bose._request = fake_request
    result = await bose.get_product_settings()
    assert result == dummy_settings


# --- Testing Bluetooth functions ---
@pytest.mark.asyncio
async def test_get_bluetooth_source_status():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_source_status = {
        "devices": []
    }
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        assert resource == "/bluetooth/source/status"
        assert method == "GET"
        return dummy_source_status
    bose._request = fake_request  # type: ignore
    result = await bose.get_bluetooth_source_status()
    assert result == dummy_source_status


@pytest.mark.asyncio
async def test_get_bluetooth_sink_status():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_sink_status = {
        "activeDevice": "3c:5e:b2:f5:c1:25",
        "devices": [
            {
                "deviceClass": "7A020C",
                "mac": "3c:5e:b2:f5:c1:25",
                "name": "Test Phone"
            }
        ],
        "status": "APP_CONNECTED"
    }
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        assert resource == "/bluetooth/sink/status"
        assert method == "GET"
        return dummy_sink_status
    bose._request = fake_request  # type: ignore
    result = await bose.get_bluetooth_sink_status()
    assert result == dummy_sink_status
    assert result.get("activeDevice") == "3c:5e:b2:f5:c1:25"  # type: ignore
    assert len(result.get("devices", [])) == 1  # type: ignore
    assert result.get("devices", [])[0]["name"] == "Test Phone"  # type: ignore


@pytest.mark.asyncio
async def test_get_bluetooth_sink_status_pairable():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_sink_status = {
        "devices": [],
        "status": "APP_PAIRABLE"
    }
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        return dummy_sink_status
    bose._request = fake_request  # type: ignore
    result = await bose.get_bluetooth_sink_status()
    assert result.get("status") == "APP_PAIRABLE"  # type: ignore
    assert len(result.get("devices", [])) == 0  # type: ignore


@pytest.mark.asyncio
async def test_get_bluetooth_sink_list():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    dummy_sink_list = {
        "devices": [
            {
                "deviceClass": "38010C",
                "mac": "df:12:af:0c:6b:ba",
                "name": "Test MacBook Pro"
            },
            {
                "deviceClass": "7A020C",
                "mac": "3c:5e:b2:f5:c1:25", 
                "name": "Test Phone"
            }
        ]
    }
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        assert resource == "/bluetooth/sink/list"
        assert method == "GET"
        return dummy_sink_list
    bose._request = fake_request  # type: ignore
    result = await bose.get_bluetooth_sink_list()
    assert result == dummy_sink_list
    assert len(result.get("devices", [])) == 2  # type: ignore
    assert result.get("devices", [])[0]["name"] == "Test MacBook Pro"  # type: ignore
    assert result.get("devices", [])[1]["name"] == "Test Phone"  # type: ignore


@pytest.mark.asyncio
async def test_set_bluetooth_sink_pairable():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    captured_args = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_args
        if body is None:
            body = {}
        captured_args = (resource, method, body)
        return {}
    bose._request = fake_request  # type: ignore
    await bose.set_bluetooth_sink_pairable()
    assert captured_args is not None
    assert captured_args[0] == "/bluetooth/sink/pairable"
    assert captured_args[1] == "POST"
    assert captured_args[2] == {}


@pytest.mark.asyncio
async def test_connect_bluetooth_sink_device():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    mac_address = "3c:5e:b2:f5:c1:25"
    captured_args = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_args
        if body is None:
            body = {}
        captured_args = (resource, method, body)
        return {}
    bose._request = fake_request  # type: ignore
    await bose.connect_bluetooth_sink_device(mac_address)
    assert captured_args is not None
    assert captured_args[0] == "/bluetooth/sink/connect"
    assert captured_args[1] == "POST"
    assert captured_args[2] == {"mac": mac_address}


@pytest.mark.asyncio
async def test_disconnect_bluetooth_sink_device():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    mac_address = "3c:5e:b2:f5:c1:25"
    captured_args = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_args
        if body is None:
            body = {}
        captured_args = (resource, method, body)
        return {}
    bose._request = fake_request  # type: ignore
    await bose.disconnect_bluetooth_sink_device(mac_address)
    assert captured_args is not None
    assert captured_args[0] == "/bluetooth/sink/disconnect"
    assert captured_args[1] == "POST"
    assert captured_args[2] == {"mac": mac_address}


@pytest.mark.asyncio
async def test_remove_bluetooth_sink_device():
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    mac_address = "3c:5e:b2:f5:c1:25"
    captured_args = None
    async def fake_request(resource, method, body=None, **kwargs):
        nonlocal captured_args
        if body is None:
            body = {}
        captured_args = (resource, method, body)
        return {}
    bose._request = fake_request  # type: ignore
    await bose.remove_bluetooth_sink_device(mac_address)
    assert captured_args is not None
    assert captured_args[0] == "/bluetooth/sink/remove"
    assert captured_args[1] == "POST"
    assert captured_args[2] == {"mac": mac_address}


@pytest.mark.asyncio
async def test_bluetooth_connection_workflow():
    """Test a complete Bluetooth connection workflow based on bluetooth.json"""
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    
    request_calls = []
    
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        request_calls.append((resource, method, body))
        
        # Simulate different responses based on the request
        if resource == "/bluetooth/sink/list" and method == "GET":
            if len(request_calls) == 1:  # First call - empty list
                return {"devices": []}
            else:  # After pairing - device appears
                return {
                    "devices": [
                        {
                            "deviceClass": "38010C",
                            "mac": "df:12:af:0c:6b:ba",
                            "name": "Test MacBook Pro"
                        }
                    ]
                }
        elif resource == "/bluetooth/sink/status" and method == "GET":
            if len(request_calls) <= 2:  # Before connection
                return {"devices": [], "status": "APP_PAIRABLE"}
            else:  # After connection
                return {
                    "activeDevice": "df:12:af:0c:6b:ba",
                    "devices": [
                        {
                            "deviceClass": "38010C",
                            "mac": "df:12:af:0c:6b:ba",
                            "name": "Test MacBook Pro"
                        }
                    ],
                    "status": "APP_CONNECTED"
                }
        elif resource == "/bluetooth/sink/pairable" and method == "POST":
            return {}
        elif resource == "/bluetooth/sink/connect" and method == "POST":
            return {}
        else:
            return {}
    
    bose._request = fake_request  # type: ignore
    
    # Step 1: Get initial device list (should be empty)
    device_list = await bose.get_bluetooth_sink_list()
    assert len(device_list.get("devices", [])) == 0  # type: ignore
    
    # Step 2: Check initial status (should be pairable)
    status = await bose.get_bluetooth_sink_status()
    assert status.get("status") == "APP_PAIRABLE"  # type: ignore
    
    # Step 3: Make device pairable
    await bose.set_bluetooth_sink_pairable()
    
    # Step 4: After pairing, device appears in list
    device_list = await bose.get_bluetooth_sink_list()
    assert len(device_list.get("devices", [])) == 1  # type: ignore
    assert device_list.get("devices", [])[0]["name"] == "Test MacBook Pro"  # type: ignore
    
    # Step 5: Connect to the device
    mac_address = device_list.get("devices", [])[0]["mac"]  # type: ignore
    await bose.connect_bluetooth_sink_device(mac_address)
    
    # Step 6: Check final status (should be connected)
    final_status = await bose.get_bluetooth_sink_status()
    assert final_status.get("status") == "APP_CONNECTED"  # type: ignore
    assert final_status.get("activeDevice") == mac_address  # type: ignore
    
    # Verify the correct sequence of API calls
    assert len(request_calls) == 6
    assert request_calls[0] == ("/bluetooth/sink/list", "GET", {})
    assert request_calls[1] == ("/bluetooth/sink/status", "GET", {})
    assert request_calls[2] == ("/bluetooth/sink/pairable", "POST", {})
    assert request_calls[3] == ("/bluetooth/sink/list", "GET", {})
    assert request_calls[4] == ("/bluetooth/sink/connect", "POST", {"mac": mac_address})
    assert request_calls[5] == ("/bluetooth/sink/status", "GET", {})


@pytest.mark.asyncio
async def test_bluetooth_disconnection_workflow():
    """Test Bluetooth disconnection workflow based on bluetooth.json"""
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    
    request_calls = []
    
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        request_calls.append((resource, method, body))
        
        # Simulate different responses based on the request sequence
        if resource == "/bluetooth/sink/status" and method == "GET":
            if len(request_calls) == 1:  # Initially connected
                return {
                    "activeDevice": "3c:5e:b2:f5:c1:25",
                    "devices": [
                        {
                            "deviceClass": "7A020C",
                            "mac": "3c:5e:b2:f5:c1:25",
                            "name": "Test Phone"
                        }
                    ],
                    "status": "APP_CONNECTED"
                }
            else:  # After disconnection
                return {
                    "devices": [],
                    "status": "APP_PAIRABLE"
                }
        elif resource == "/bluetooth/sink/disconnect" and method == "POST":
            return {}
        else:
            return {}
    
    bose._request = fake_request  # type: ignore
    
    # Step 1: Check initial status (should be connected)
    status = await bose.get_bluetooth_sink_status()
    assert status.get("status") == "APP_CONNECTED"  # type: ignore
    assert status.get("activeDevice") == "3c:5e:b2:f5:c1:25"  # type: ignore
    
    # Step 2: Disconnect the device
    mac_address = status.get("activeDevice")  # type: ignore
    assert mac_address is not None
    await bose.disconnect_bluetooth_sink_device(mac_address)
    
    # Step 3: Check final status (should be pairable)
    final_status = await bose.get_bluetooth_sink_status()
    assert final_status.get("status") == "APP_PAIRABLE"  # type: ignore
    assert len(final_status.get("devices", [])) == 0  # type: ignore
    
    # Verify the correct sequence of API calls
    assert len(request_calls) == 3
    assert request_calls[0] == ("/bluetooth/sink/status", "GET", {})
    assert request_calls[1] == ("/bluetooth/sink/disconnect", "POST", {"mac": mac_address})
    assert request_calls[2] == ("/bluetooth/sink/status", "GET", {})


@pytest.mark.asyncio
async def test_bluetooth_device_management():
    """Test Bluetooth device management operations (remove/unpair)"""
    auth = BoseAuth()
    auth.set_access_token("dummy_token", "dummy_refresh_token", "dummy_person_id")
    bose = BoseSpeaker(bose_auth=auth, host="dummy_host", device_id="device1")
    
    request_calls = []
    
    async def fake_request(resource, method, body=None, **kwargs):
        if body is None:
            body = {}
        request_calls.append((resource, method, body))
        
        if resource == "/bluetooth/sink/list" and method == "GET":
            if len(request_calls) == 1:  # Initially has devices
                return {
                    "devices": [
                        {
                            "deviceClass": "38010C",
                            "mac": "df:12:af:0c:6b:ba",
                            "name": "Test MacBook Pro"
                        },
                        {
                            "deviceClass": "7A020C",
                            "mac": "3c:5e:b2:f5:c1:25",
                            "name": "Test Phone"
                        }
                    ]
                }
            else:  # After removal
                return {
                    "devices": [
                        {
                            "deviceClass": "38010C",
                            "mac": "df:12:af:0c:6b:ba",
                            "name": "Test MacBook Pro"
                        }
                    ]
                }
        elif resource == "/bluetooth/sink/remove" and method == "POST":
            return {}
        else:
            return {}
    
    bose._request = fake_request  # type: ignore
    
    # Step 1: Get device list
    device_list = await bose.get_bluetooth_sink_list()
    assert len(device_list.get("devices", [])) == 2  # type: ignore
    
    # Step 2: Remove one device
    device_to_remove = device_list.get("devices", [])[1]["mac"]  # type: ignore
    await bose.remove_bluetooth_sink_device(device_to_remove)
    
    # Step 3: Verify device was removed
    updated_list = await bose.get_bluetooth_sink_list()
    assert len(updated_list.get("devices", [])) == 1  # type: ignore
    
    # Verify the correct sequence of API calls
    assert len(request_calls) == 3
    assert request_calls[0] == ("/bluetooth/sink/list", "GET", {})
    assert request_calls[1] == ("/bluetooth/sink/remove", "POST", {"mac": device_to_remove})
    assert request_calls[2] == ("/bluetooth/sink/list", "GET", {})