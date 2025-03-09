import requests
import time
import json
import logging
import sys
import jwt
from typing import TypedDict, Optional, Dict, Any, cast

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

# --- API Types ---

# For socialize.us1.gigya.com /socialize.getSDKConfig
class SocializeSDKConfigResponseIds(TypedDict):
    gmid: str
    ucid: str

class SocializeSDKConfigResponse(TypedDict, total=False):
    appIds: Dict[str, Any]
    callId: str
    errorCode: int
    errorReportRules: list[Any]
    ids: SocializeSDKConfigResponseIds
    permissions: Dict[str, list[str]]
    statusCode: int
    statusReason: str
    time: str

# For accounts.us1.gigya.com /accounts.login
class AccountsLoginResponseSessionInfo(TypedDict):
    sessionToken: str
    sessionSecret: str

class AccountsLoginResponseUserInfo(TypedDict):
    UID: str
    signatureTimestamp: str
    UIDSignature: str

class AccountsLoginResponse(TypedDict):
    sessionInfo: AccountsLoginResponseSessionInfo
    userInfo: AccountsLoginResponseUserInfo

# For accounts.us1.gigya.com /accounts.getJWT
class AccountsGetJWTResponse(TypedDict):
    apiVersion: int
    callId: str
    errorCode: int
    id_token: str
    statusCode: int
    statusReason: str
    time: str

# For id.api.bose.io /id-jwt-core/token
class IDJwtCoreTokenResponse(TypedDict):
    access_token: str
    bosePersonID: str
    expires_in: int
    refresh_token: str
    scope: str
    token_type: str

# For users.api.bose.io /passport-core/products/...
class UsersApiBoseProductResponse(TypedDict, total=False):
    attributes: Dict[str, Any]
    createdOn: str
    groups: list[Any]
    persons: Dict[str, str]
    presets: Dict[str, Any]
    productColor: int
    productID: str
    productType: str
    serviceAccounts: list[Dict[str, Any]]
    settings: Dict[str, Any]
    updatedOn: str
    users: Dict[str, Any]

# --- Internal Types ---

# Existing control token type expected by users of getControlToken
class ControlToken(TypedDict):
    access_token: str
    refresh_token: str
    bose_person_id: str

# Internal raw token type is now based on the IDJwtCoreTokenResponse
RawControlToken = IDJwtCoreTokenResponse

# For internal login response conversion
class LoginResponse(TypedDict):
    session_token: str
    session_secret: str
    uid: str
    signatureTimestamp: str
    UIDSignature: str

# --- BoseAuth Class ---

class BoseAuth:
    GIGYA_API_KEY: str = "3_7PoVX7ELjlWyppFZFGia1Wf1rNGZv_mqVgtqVmYl3Js-hQxZiFIU8uHxd8G6PyNz"
    GIGYA_UA: str = "Bose/32768 MySSID/1568.300.101 Darwin/24.2.0"
    BOSE_API_KEY: str = "67616C617061676F732D70726F642D6D61647269642D696F73"

    def __init__(self) -> None:
        self._control_token: Optional[RawControlToken] = None
        self._email: Optional[str] = None
        self._password: Optional[str] = None

    def _get_ids(self) -> Optional[Dict[str, str]]:
        """
        Start a session and get the GMID and UCID using the Socialize SDK Config endpoint.
        """
        logging.debug("Getting GMID and UCID")
        url: str = "https://socialize.us1.gigya.com/socialize.getSDKConfig"
        data: Dict[str, Any] = {
            "apikey": self.GIGYA_API_KEY,
            "format": "json",
            "httpStatusCodes": False,
            "include": "permissions,ids,appIds",
            "sdk": "ios_swift_1.0.8",
            "targetEnv": "mobile",
        }
        try:
            response_json: Dict[str, Any] = requests.post(url, data=data).json()
            config: SocializeSDKConfigResponse = cast(SocializeSDKConfigResponse, response_json)
        except Exception as e:
            logging.error(f"Error getting GMID and UCID: {e}")
            return None

        logging.debug(f"_get_ids: {json.dumps(config, indent=4)}")
        ids = config.get("ids")
        if ids and "gmid" in ids and "ucid" in ids:
            return {"gmid": ids["gmid"], "ucid": ids["ucid"]}
        return None

    def _login(self, email: str, password: str, gmid: str, ucid: str) -> LoginResponse:
        """
        Login to Gigya using the accounts.login endpoint.
        """
        logging.debug(f"Logging in with {email}, gmid {gmid}, ucid {ucid}")
        url: str = "https://accounts.us1.gigya.com/accounts.login"
        headers: Dict[str, str] = {
            "Host": "accounts.us1.gigya.com",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": self.GIGYA_UA,
            "Accept-Language": "de-DE,de;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data: Dict[str, Any] = {
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
        response_obj: requests.Response = requests.post(url, headers=headers, data=data)
        if response_obj.status_code == 200:
            json_response: Dict[str, Any] = response_obj.json()
            logging.debug("WARNING! CONFIDENTIAL INFORMATION! REMOVE AT LEAST THE session_secret AND UIDSignature FROM THE LOGS!")
            logging.debug(f"_login: {json.dumps(json_response, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
            login_resp: AccountsLoginResponse = cast(AccountsLoginResponse, json_response)
            return {
                "session_token": login_resp["sessionInfo"]["sessionToken"],
                "session_secret": login_resp["sessionInfo"]["sessionSecret"],
                "uid": login_resp["userInfo"]["UID"],
                "signatureTimestamp": login_resp["userInfo"]["signatureTimestamp"],
                "UIDSignature": login_resp["userInfo"]["UIDSignature"],
            }
        else:
            raise ValueError(f"Login failed: {response_obj.text}")

    def _get_jwt(self, user: LoginResponse, gmid: str, ucid: str) -> Optional[str]:
        """
        Get the authentication token from Gigya using the accounts.getJWT endpoint.
        """
        url: str = "https://accounts.us1.gigya.com/accounts.getJWT"
        headers: Dict[str, str] = {
            "Host": "accounts.us1.gigya.com",
            "Connection": "keep-alive",
            "Accept": "*/*",
            "User-Agent": self.GIGYA_UA,
            "Accept-Language": "de-DE,de;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        timestamp: str = str(int(time.time()))
        params: Dict[str, Any] = {
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
        base_string: str = request.calcOAuth1BaseString("POST", url, True, params)
        sig: str = SigUtils.calcSignature(base_string, user["session_secret"])
        params["sig"] = sig

        try:
            logging.debug("WAARNING! CONFIDENTIAL INFORMATION!")
            response_json: Dict[str, Any] = requests.post(url, headers=headers, data=params).json()
            jwt_resp: AccountsGetJWTResponse = cast(AccountsGetJWTResponse, response_json)
            logging.debug(f"_get_jwt: {json.dumps(jwt_resp, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
        except Exception as e:
            logging.error(f"Error getting JWT: {e}")
            return None
        return jwt_resp.get("id_token")

    def do_token_refresh(self, access_token: Optional[str] = None, refresh_token: Optional[str] = None) -> ControlToken:
        """
        Refresh the control token using the /id-jwt-core/token endpoint.
        If access_token and refresh_token are not provided, the previously fetched tokens will be used.
        """
        if self._control_token is None:
            raise ValueError("No control token stored to refresh.")
        if access_token is None:
            access_token = self._control_token.get("access_token")
        if refresh_token is None:
            refresh_token = self._control_token.get("refresh_token")
            
        if access_token is None or refresh_token is None:
            raise ValueError("Provide both the access_token and refresh_token or the control token")
        
        fetched: Optional[RawControlToken] = self._fetch_keys(access_token=access_token, refresh_token=refresh_token)
        if fetched is None:
            raise ValueError("Failed to refresh token")
        self._control_token = fetched
        return {
            "access_token": self._control_token.get("access_token"),
            "refresh_token": self._control_token.get("refresh_token"),
            "bose_person_id": self._control_token.get("bosePersonID", ""),
        }

    def _fetch_keys(
        self,
        gigya_jwt: Optional[str] = None,
        signature_timestamp: Optional[str] = None,
        uid: Optional[str] = None,
        uid_signature: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None
    ) -> Optional[RawControlToken]:
        """
        Fetch the local control token from the id.api.bose.io endpoint.
        Either provide the gigya_jwt, signature_timestamp, uid and uid_signature or the access_token and refresh_token.
        """
        if (gigya_jwt is None or signature_timestamp is None or uid is None or uid_signature is None) and (access_token is None or refresh_token is None):
            raise ValueError("Provide either the gigya_jwt, signature_timestamp, uid and uid_signature or the access_token and refresh_token")
        
        url: str = "https://id.api.bose.io/id-jwt-core/token"
        headers: Dict[str, str] = {
            "X-ApiKey": self.BOSE_API_KEY,
            "X-Software-Version": "10.6.6-32768",
            "X-Api-Version": "1",
            "User-Agent": "MadridApp/10.6.6 (com.bose.bosemusic; build:32768; iOS 18.3.0) Alamofire/5.6.2",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache"
        }
        
        if access_token is not None and refresh_token is not None:
            data: Dict[str, Any] = {
                "scope": "openid",
                "client_id": self.BOSE_API_KEY,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token
            }
        else:
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
            response_json: Dict[str, Any] = requests.post(url, headers=headers, json=data).json()
            logging.debug("WARNING! CONFIDENTIAL INFORMATION!")
            logging.debug(f"_fetch_keys: {json.dumps(response_json, indent=4)}")
            logging.debug("END OF CONFIDENTIAL INFORMATION!")
        except Exception as e:
            logging.error(f"Error fetching keys: {e}")
            return None
        token_resp: IDJwtCoreTokenResponse = cast(IDJwtCoreTokenResponse, response_json)
        return token_resp

    def is_token_valid(self, token: str) -> bool:
        """
        Check if the token is still valid by decoding it without verifying signature.
        """
        try:
            decoded: Dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
            exp: int = decoded.get("exp", 0)
            valid: bool = exp > int(time.time())
            # Update control token if valid (only setting access_token)
            if self._control_token is None:
                self._control_token = {"access_token": token}
            else:
                self._control_token["access_token"] = token
            return valid
        except Exception:
            return False

    def getControlToken(self, email: Optional[str] = None, password: Optional[str] = None, forceNew: bool = False) -> ControlToken:
        """
        Get the control token to access the local speaker API.
        """
        if not forceNew and self._control_token is not None:
            access_token: Optional[str] = self._control_token.get("access_token")
            if access_token and self.is_token_valid(access_token):
                return {
                    "access_token": access_token,
                    "refresh_token": self._control_token.get("refresh_token", ""),
                }
            else:
                logging.debug("Token is expired. Trying to refresh token")
                
        if email is not None:
            self._email = email
        if password is not None:
            self._password = password

        if self._email is None or self._password is None:
            raise ValueError("Email and password are required for the first call!")

        ids = self._get_ids()
        if ids is None:
            raise ValueError("Could not retrieve GMID and UCID")
        gmid: str = ids["gmid"]
        ucid: str = ids["ucid"]

        user: LoginResponse = self._login(self._email, self._password, gmid, ucid)
        gigya_jwt: Optional[str] = self._get_jwt(user, gmid, ucid)
        if gigya_jwt is None:
            raise ValueError("Failed to retrieve Gigya JWT")

        fetched: Optional[RawControlToken] = self._fetch_keys(
            gigya_jwt, user["signatureTimestamp"], user["uid"], user["UIDSignature"]
        )
        if fetched is None:
            raise ValueError("Failed to fetch control token")
        self._control_token = fetched
        return {
            "access_token": self._control_token.get("access_token"),
            "refresh_token": self._control_token.get("refresh_token", ""),
            "bose_person_id": self._control_token.get("bosePersonID", ""),
        }

    def fetchProductInformation(self, gwid: str) -> Optional[BoseApiProduct]:
        """
        Fetch product information from the users.api.bose.io endpoint.
        """
        url: str = f"https://users.api.bose.io/passport-core/products/{gwid}"
        headers: Dict[str, str] = {
            "X-ApiKey": self.BOSE_API_KEY,
            "X-Software-Version": "10.6.6-32768",
            "X-Api-Version": "1",
            "User-Agent": "MadridApp/10.6.6 (com.bose.bosemusic; build:32768; iOS 18.3.0) Alamofire/5.6.2",
            "X-User-Token": self._control_token.get("access_token") if self._control_token else "",
        }
        try:
            response_json: Dict[str, Any] = requests.get(url, headers=headers).json()
            logging.debug(f"product info: {json.dumps(response_json, indent=4)}")
        except Exception as e:
            logging.error(f"Error fetching product information: {e}")
            return None
        product_resp: UsersApiBoseProductResponse = cast(UsersApiBoseProductResponse, response_json)
        return BoseApiProduct(**product_resp)