import requests
import time
import json
import logging
import sys
import jwt
from .GSSDK import GSRequest, SigUtils
from .BoseCloudResponse import BoseApiProduct

"""
ALL API KEYS ARE PUBLICLY AVAILABLE ON THE BOSE WEBSITE
THESE ARE NOT SENSITIVE INFORMATION AND THEREFORE CAN BE SHARED IN THIS SCRIPT

This script allows you to obtain a control token from the BOSE online api in order to control your BOSE speaker locally.
The obtained token is a JWT with a limited lifetime and needs to be refreshed from time to time. This script currently does not support refreshing the token. (Feel free to add it!)
So you need to refetch the token from time to time. Please cache the token, to avoid many api calls. I dont know if there is a rate limit or something like that.

This api was not documented by BOSE and is not officially supported, but was revered engineered by analyzing the BOSE app's api calls.
So it may stop working at any time.

IMPORTANT:
Just be respectful and dont spam the api with requests.
Otherwise BOSE may block this project all together.
"""


class BoseAuth:
    GIGYA_API_KEY = "3_7PoVX7ELjlWyppFZFGia1Wf1rNGZv_mqVgtqVmYl3Js-hQxZiFIU8uHxd8G6PyNz"
    GIGYA_UA = "Bose/32768 MySSID/1568.300.101 Darwin/24.2.0"

    BOSE_API_KEY = "67616C617061676F732D70726F642D6D61647269642D696F73"

    def __init__(self):
        self._control_token = None

    def _get_ids(self):
        """
        Start a session and get the GMID and UCID
        """
        logging.debug("Getting GMID and UCID")

        url = "https://socialize.us1.gigya.com/socialize.getSDKConfig"
        data = {
            "apikey": self.GIGYA_API_KEY,
            "format": "json",
            "httpStatusCodes": False,
            "include": "permissions,ids,appIds",
            "sdk": "ios_swift_1.0.8",
            "targetEnv": "mobile",
        }
        try:
            response = requests.post(url, data=data).json()
        except Exception as e:
            logging.error(f"Error getting GMID and UCID: {e}")
            return None

        logging.debug(f"_get_ids: {json.dumps(response, indent=4)}")
        return {
            "gmid": response.get("ids", {}).get("gmid"),
            "ucid": response.get("ids", {}).get("ucid"),
        }

    def _login(self, email, password, gmid, ucid):
        """
        Login to Gigya
        """

        logging.debug(f"Logging in with {email}, gmid {gmid}, ucid {ucid}")
        url = "https://accounts.us1.gigya.com/accounts.login"
        headers = {
            "Host": "accounts.us1.gigya.com",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": self.GIGYA_UA,
            "Accept-Language": "de-DE,de;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "apikey": self.GIGYA_API_KEY,
            "format": "json",
            "gmid": gmid,
            "httpStatusCodes": "false",
            "include": "profile,data,emails,subscriptions,preferences,",
            "includeUserInfo": "true",
            "lang": "de",
            "loginID": email,
            "loginMode": "standard",
            "password": password,
            "sdk": "ios_swift_1.0.8",
            "sessionExpiration": "0",
            "source": "showScreenSet",
            "targetEnv": "mobile",
            "ucid": ucid,
        }
        response = requests.post(url, headers=headers, data=data)

        if response.status_code == 200:
            json_response = response.json()
            logging.debug(
                "WARNING! CONFIDENTIAL INFORMATION! REMOVE AT LEAST THE session_secret AND UIDSignature FROM THE LOGS!"
            )
            logging.debug(f"_login: {json.dumps(json_response, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
            return {
                "session_token": json_response.get("sessionInfo", {}).get(
                    "sessionToken"
                ),
                "session_secret": json_response.get("sessionInfo", {}).get(
                    "sessionSecret"
                ),
                "uid": json_response.get("userInfo", {}).get("UID"),
                "signatureTimestamp": json_response.get("userInfo", {}).get(
                    "signatureTimestamp"
                ),
                "UIDSignature": json_response.get("userInfo", {}).get("UIDSignature"),
            }
        else:
            raise ValueError(f"Login failed: {response.text}")

    def _get_jwt(self, user, gmid, ucid):
        """
        Get the authentication token from Gigya
        """

        url = "https://accounts.us1.gigya.com/accounts.getJWT"
        headers = {
            "Host": "accounts.us1.gigya.com",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": self.GIGYA_UA,
            "Accept-Language": "de-DE,de;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        timestamp = str(int(time.time()))
        params = {
            "apikey": self.GIGYA_API_KEY,
            "format": "json",
            "gmid": gmid,
            "httpStatusCodes": "false",
            "nonce": f"{timestamp}_1637928129",
            "oauth_token": user["session_token"],
            "sdk": "ios_swift_1.0.8",
            "targetEnv": "mobile",
            "timestamp": timestamp,
            "ucid": ucid,
        }

        request = GSRequest()
        base_string = request.calcOAuth1BaseString("POST", url, True, params)
        sig = SigUtils.calcSignature(base_string, user["session_secret"])
        params["sig"] = sig

        try:
            logging.debug("WAARNING! CONFIDENTIAL INFORMATION!")
            response = requests.post(url, headers=headers, data=params).json()
            logging.debug(f"_get_jwt: {json.dumps(response, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
        except Exception as e:
            logging.error(f"Error getting JWT: {e}")
            return None
        return response.get("id_token")

    def _fetch_keys(self, gigya_jwt, signature_timestamp, uid, uid_signature):
        """
        Fetch the local control token
        """
        url = "https://id.api.bose.io/id-jwt-core/token"
        headers = {
            "X-ApiKey": self.BOSE_API_KEY,
            "X-Software-Version": "10.6.6-32768",
            "X-Api-Version": "1",
            "User-Agent": "MadridApp/10.6.6 (com.bose.bosemusic; build:32768; iOS 18.3.0) Alamofire/5.6.2",
        }
        data = {
            "id_token": gigya_jwt,
            "scope": "openid",
            "grant_type": "id_token",
            "signature_timestamp": signature_timestamp,
            "uid_signature": uid_signature,
            "uid": uid,
            "client_id": self.BOSE_API_KEY,
        }

        try:
            response = requests.post(url, headers=headers, json=data).json()
            logging.debug("WARNING! CONFIDENTIAL INFORMATION!")
            logging.debug(f"_fetch_keys: {json.dumps(response, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
        except Exception as e:
            logging.error(f"Error fetching keys: {e}")
            return None
        return response

    def is_token_valid(self, token):
        """
        Check if the token is still valid
        """
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp = decoded.get("exp", 0)

            valid = exp > int(time.time())
            self._control_token = {
                "access_token": token,
            }
            return valid
        except Exception:
            return False

    # TODO: Implement refresh token
    def getControlToken(self, email=None, password=None, forceNew=False):
        """
        Get the control token to access the local speaker API
        """
        if not forceNew and self._control_token is not None:
            access_token = self._control_token.get("access_token")
            if access_token and self.is_token_valid(access_token):
                return {
                    "access_token": access_token,
                    "refresh_token": self._control_token.get("refresh_token"),
                }

        if email is not None:
            self._email = email
        if password is not None:
            self._password = password

        if self._email is None or self._password is None:
            raise ValueError("Email and password are required for the first call!")

        ids = self._get_ids()
        gmid, ucid = ids["gmid"], ids["ucid"]

        user = self._login(self._email, self._password, gmid, ucid)
        gigya_jwt = self._get_jwt(user, gmid, ucid)

        self._control_token = self._fetch_keys(
            gigya_jwt, user["signatureTimestamp"], user["uid"], user["UIDSignature"]
        )
        return {
            "access_token": self._control_token.get("access_token"),
            "refresh_token": self._control_token.get("refresh_token"),
            "bose_person_id": self._control_token.get("bosePersonID"),
        }

    def fetchProductInformation(self, gwid: str) -> BoseApiProduct:
        url = "https://users.api.bose.io/passport-core/products/{}".format(gwid)
        headers = {
            "X-ApiKey": self.BOSE_API_KEY,
            "X-Software-Version": "10.6.6-32768",
            "X-Api-Version": "1",
            "User-Agent": "MadridApp/10.6.6 (com.bose.bosemusic; build:32768; iOS 18.3.0) Alamofire/5.6.2",
            "X-User-Token": self._control_token.get("access_token"),
        }

        try:
            response = requests.get(url, headers=headers).json()
            logging.debug(f"product info: {json.dumps(response, indent=4)}")
        except Exception as e:
            logging.error(f"Error fetching keys: {e}")
            return None
        return BoseApiProduct(**response)


# EXAMPLE USAGE

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]

    bose_auth = BoseAuth()
    control_token = bose_auth.getControlToken(email, password)
    print(json.dumps(control_token, indent=4))
