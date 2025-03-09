from pybose import BoseAuth
import json
import sys

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]

    bose_auth = BoseAuth()
    control_token = bose_auth.getControlToken(email, password)
    print(json.dumps(control_token, indent=4))