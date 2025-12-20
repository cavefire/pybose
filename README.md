# Unofficial Bose API for Soundbars and Speakers

[![Python Tests](https://github.com/cavefire/pybose/actions/workflows/python-tests.yml/badge.svg)](https://github.com/cavefire/pybose/actions/workflows/python-tests.yml)

This Python project provides an unofficial API to control Bose Soundbars and Speakers locally. The API was reverse-engineered by analyzing the Bose app's API calls and is **not officially supported by Bose**. It allows users to interact with their Bose devices through local network communication and provides a basic feature set for device control.

Also check out my Homeassistant integration: [Bose-Homeassistant](https://github.com/cavefire/Bose-Homeassistant)

### Tested Devices
- Bose Soundbar Ultra
- Bose Soundbar 900
- Bose Music Amplifier
- Bose Soundbar 700
- Bose Portable Speaker

Other Bose devices may also work, but they have not been tested.

---

## Installation

```bash
pip install pybose
```

## Usage

### BoseAuth
BOSE decided that in order to control your devices locally (!) you still need to acquire a token from their cloud. This is done by using the `BoseAuth` class. 

Sadly there is no official documentation about this (at least none I could find), so I had to reverse engineer the API calls the official app makes. 

**Note:** The token is a JWT with a limited lifetime and needs to be refreshed manually. Consider caching the token to reduce API calls.

#### Usage of `BoseAuth`
```python
bose_auth = BoseAuth()
control_token = bose_auth.getControlToken(email, password)

access_token = control_token['access_token']
refresh_token = control_token['refresh_token']
```

---

### BoseDiscovery
After you got your access token, you can begin by discovering your devices on the network. Therefore you can use the `BoseDiscovery` class.

```python
discovery = BoseDiscovery()
devices = discovery.discover_devices()
for device in devices:
    print(f"GUID: {device['GUID']}, IP: {device['IP']}")
```

You will need not only the **IP**, but also the **GUID** to connect to the device.

---

### BoseDevice
Now you are ready to finally control your speaker! You can use the `BoseSpeaker` class to interact with your device.

```python
bose = BoseSpeaker(
    bose_auth=auth
    device_id="your_device_GUID",
    host="your_device_IP"
)

bose.attach_receiver(lambda data: print(f"Received unsolicited message: {json.dumps(data, indent=4)}"))

await bose.connect()
response = await bose.set_power_state(True)
await bose.disconnect()
```

After attaching to the speaker, you can use the following functions:
* get_capabilities
* get_system_info
* get_audio_volume
* set_audio_volume
* get_now_playing
* get_bluetooth_status
* get_power_state
* set_power_state
* pause
* play
* skip_next
* skip_previous
* get_device_id
* subscribe
* switch_tv_source
* set_source
* get_sources
* get_audio_settings
* set_audio_settings
* get_accessories
* get_battery_status

**Note:** The device supports more. But for now, these are the only functions implemented. Feel free to add more, or open an issue if you have a specific need.

## Development

### Running Tests

This project includes both unit tests and integration tests.

#### Unit Tests
Unit tests mock external dependencies and can be run without credentials:

```bash
python -m pytest tests/unit/ -v
```

#### Integration Tests
Integration tests require real Bose account credentials and test against actual Bose APIs. Set the following environment variables:

```bash
export BOSE_EMAIL="your_email@example.com"
export BOSE_PASSWORD="your_password"
export BOSE_GWID="your_device_gwid"  # Optional, for product information tests
```

Run integration tests:

```bash
# Run all integration tests
python -m pytest tests/integration/ -v -m integration

# Run specific integration test
python -m pytest tests/integration/test_bose_auth_integration.py -v -m integration
```

#### Coverage Reports
Generate coverage reports in XML and JSON format:

```bash
python -m pytest tests/unit/ --cov=pybose --cov-report=xml --cov-report=json --cov-report=term
```

## Limitations
* **Unofficial API:** The API is not officially supported by Bose and may break at any time.
* **Token Lifetime:** The token has a limited lifetime and needs to be refreshed manually.
* **Rate Limiting:** The API may be rate-limited by Bose if too many requests are made in a short period of time.

## Contributing
This project is a work in progress, and contributions are welcome!
If you encounter issues, have feature requests, or want to contribute, feel free to submit a pull request or open an issue.

The file `AvailableMethods.txt` contains a list of all available `resources` I could find.
Best way to find out, what data these functions need, is to use the official app and sniff the network traffic. I used `Proxymon` for this. There should be a websocket connection to `ws://<device_ip>:8082` which contains all the data you need.

## Wishlist

The first item on my wishlist is a **Homeassistant** integration. I am currently working on this here: [Bose-Homeassistant](https://github.com/cavefire/Bose-Homeassistant)

**Other items on my wishlist:**

- [x] Implement token refresh
- [x] Implement groups
- [x] Implement source (TV / Optical / AUX) switching
- [ ] Implement source (Bluetooth) switching
- [x] Implement equalizer settings
- [x] Implement bass module settings
- [x] Implement surround speaker settings

And lastly, a way to not use the BOSE cloud at all would be nice. But I am not sure, if this is possible at all.

## Disclaimer
This project is not affiliated with Bose Corporation. The API is reverse-engineered and may break at any time. Use at your own risk.

**Be respectful and avoid spamming the API with unnecessary requests to ensure this project remains functional for everyone.**


**To the BOSE legal team:**

All API keys used in this project are publicly available on the Bose website.

There was no need to be a computer specialist to find them, so: Please do not sue me for making people use their products in a way they want to.

If you have any issues with me publishing this, please contact me! I am happy to discuss this with you and make your products better.

## License
This project is licensed under GNU GPLv3 - see the [LICENSE](LICENSE) file for details.
