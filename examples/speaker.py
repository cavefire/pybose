import sys
sys.path.append("../")

from pybose import BoseAuth, BoseSpeaker
import asyncio
import json
import sys

async def main(email: str, password: str, device_id: str, host: str) -> None:
    auth = BoseAuth()
    control_token = auth.getControlToken(email, password, forceNew=True)
    
    bose = BoseSpeaker(bose_auth=auth, device_id=device_id, host=host)
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
    if len(sys.argv) != 5:
        print(f"Usage: python {sys.argv[0]} <email> <password> <device_id> <host>")
        sys.exit(1)
    email = sys.argv[1]
    password = sys.argv[2]
    device_id_arg = sys.argv[3]
    host_arg = sys.argv[4]
    asyncio.run(main(email, password, device_id_arg, host_arg))