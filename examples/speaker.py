from pybose import BoseSpeaker
import asyncio
import json
import sys

async def main(control_token: str, device_id: str, host: str) -> None:
    bose = BoseSpeaker(control_token=control_token, device_id=device_id, host=host)
    bose.attach_receiver(lambda data: print(f"Received unsolicited message: {json.dumps(data, indent=4)}"))
    await bose.connect()
    response = await bose.get_system_info()
    print(response)
    response = await bose.get_audio_volume()
    print(response)
    response = await bose.get_now_playing()
    print(response)
    await bose.disconnect()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python {sys.argv[0]} <control_token> <device_id> <host>")
        sys.exit(1)
    control_token_arg = sys.argv[1]
    device_id_arg = sys.argv[2]
    host_arg = sys.argv[3]
    asyncio.run(main(control_token_arg, device_id_arg, host_arg))