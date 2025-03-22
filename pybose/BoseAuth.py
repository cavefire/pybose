"""
BoseAuth Module

This module provides functionality to obtain a control token from the BOSE online API,
which is used for local control of a Bose speaker. The control token is a JWT with a limited
lifetime and must be refreshed periodically. The API keys used are publicly available on the
BOSE website, so they are not considered sensitive.

Note:
    This API is not officially supported by Bose and was reverse engineered by analyzing
    the Bose app's API calls. Therefore, the API may change or stop working at any time.
    Please be respectful with the requests to avoid being blocked.
"""

import requests
import time
import json
import logging
import sys
import jwt
from typing import TypedDict, Optional, Dict, Any, cast

from .GSSDK import GSRequest, SigUtils
from .BoseCloudResponse import BoseApiProduct

# --- API Types ---

class SocializeSDKConfigResponseIds(TypedDict):
    """
    Represents the 'ids' portion of the response from the Socialize SDK Config endpoint.
    
    Attributes:
        gmid (str): The GMID value.
        ucid (str): The UCID value.
    """
    gmid: str
    ucid: str

class SocializeSDKConfigResponse(TypedDict, total=False):
    """
    Represents the full response from the Socialize SDK Config endpoint.
    
    Attributes:
        appIds (Dict[str, Any]): Application IDs (optional).
        callId (str): The call identifier.
        errorCode (int): The error code, if any.
        errorReportRules (list[Any]): Any error report rules.
        ids (SocializeSDKConfigResponseIds): The GMID and UCID values.
        permissions (Dict[str, list[str]]): Permissions by service.
        statusCode (int): HTTP status code.
        statusReason (str): HTTP status reason.
        time (str): Timestamp of the response.
    """
    appIds: Dict[str, Any]
    callId: str
    errorCode: int
    errorReportRules: list[Any]
    ids: SocializeSDKConfigResponseIds
    permissions: Dict[str, list[str]]
    statusCode: int
    statusReason: str
    time: str

class AccountsLoginResponseSessionInfo(TypedDict):
    """
    Represents session information from the accounts.login endpoint.
    
    Attributes:
        sessionToken (str): The session token.
        sessionSecret (str): The secret used for signing requests.
    """
    sessionToken: str
    sessionSecret: str

class AccountsLoginResponseUserInfo(TypedDict):
    """
    Represents user information from the accounts.login endpoint.
    
    Attributes:
        UID (str): The unique user ID.
        signatureTimestamp (str): Timestamp of the signature.
        UIDSignature (str): The UID signature.
    """
    UID: str
    signatureTimestamp: str
    UIDSignature: str

class AccountsLoginResponse(TypedDict):
    """
    Represents the complete response from the accounts.login endpoint.
    
    Attributes:
        sessionInfo (AccountsLoginResponseSessionInfo): Session info.
        userInfo (AccountsLoginResponseUserInfo): User info.
    """
    sessionInfo: AccountsLoginResponseSessionInfo
    userInfo: AccountsLoginResponseUserInfo

class AccountsGetJWTResponse(TypedDict):
    """
    Represents the response from the accounts.getJWT endpoint.
    
    Attributes:
        apiVersion (int): The API version.
        callId (str): The call identifier.
        errorCode (int): The error code.
        id_token (str): The JWT token.
        statusCode (int): The HTTP status code.
        statusReason (str): The HTTP status reason.
        time (str): The time of the response.
    """
    apiVersion: int
    callId: str
    errorCode: int
    id_token: str
    statusCode: int
    statusReason: str
    time: str

class IDJwtCoreTokenResponse(TypedDict):
    """
    Represents the response from the id.api.bose.io /id-jwt-core/token endpoint.
    
    Attributes:
        access_token (str): The access token.
        bosePersonID (str): The Bose person ID.
        expires_in (int): Token expiry time in seconds.
        refresh_token (str): The refresh token.
        scope (str): The token scope.
        token_type (str): The token type.
    """
    access_token: str
    bosePersonID: str
    expires_in: int
    refresh_token: str
    scope: str
    token_type: str

class UsersApiBoseProductResponse(TypedDict, total=False):
    """
    Represents the response from the users.api.bose.io /passport-core/products/ endpoint.
    
    Attributes:
        attributes (Dict[str, Any]): Product attributes.
        createdOn (str): Creation timestamp.
        groups (list[Any]): Groups information.
        persons (Dict[str, str]): Mapping of person IDs to roles.
        presets (Dict[str, Any]): Presets information.
        productColor (int): The color code of the product.
        productID (str): The product identifier.
        productType (str): The product type.
        serviceAccounts (list[Dict[str, Any]]): Service account details.
        settings (Dict[str, Any]): Additional settings.
        updatedOn (str): Last updated timestamp.
        users (Dict[str, Any]): Users associated with the product.
    """
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

class ControlToken(TypedDict):
    """
    Represents a control token with associated information.
    
    Attributes:
        access_token (str): The access token.
        refresh_token (str): The refresh token.
        bose_person_id (str): The Bose person identifier.
    """
    access_token: str
    refresh_token: str
    bose_person_id: str

# Internal raw token type, based on IDJwtCoreTokenResponse.
RawControlToken = IDJwtCoreTokenResponse

class LoginResponse(TypedDict):
    """
    Represents an internal structure for login responses.
    
    Attributes:
        session_token (str): The session token.
        session_secret (str): The session secret.
        uid (str): The user ID.
        signatureTimestamp (str): Timestamp for the signature.
        UIDSignature (str): The UID signature.
    """
    session_token: str
    session_secret: str
    uid: str
    signatureTimestamp: str
    UIDSignature: str

# --- BoseAuth Class ---

class BoseAuth:
    """
    A class to interact with the BOSE online API for obtaining control tokens.

    This class uses publicly available API keys to obtain a JWT control token, which is used
    to control a local Bose speaker. It also provides methods to refresh tokens and to fetch
    product information from the BOSE API.
    
    Attributes:
        GIGYA_API_KEY (str): Public API key for Gigya.
        GIGYA_UA (str): User-Agent string used for Gigya requests.
        BOSE_API_KEY (str): Public API key for the BOSE API.
    """
    GIGYA_API_KEY: str = "3_7PoVX7ELjlWyppFZFGia1Wf1rNGZv_mqVgtqVmYl3Js-hQxZiFIU8uHxd8G6PyNz"
    GIGYA_UA: str = "Bose/32768 MySSID/1568.300.101 Darwin/24.2.0"
    BOSE_API_KEY: str = "67616C617061676F732D70726F642D6D61647269642D696F73"

    def __init__(self) -> None:
        """
        Initialize a new BoseAuth instance.
        
        The control token, email, and password are initially unset.
        """
        self._control_token: Optional[RawControlToken] = None
        self._email: Optional[str] = None
        self._password: Optional[str] = None

    def _get_ids(self) -> Optional[Dict[str, str]]:
        """
        Start a session and retrieve the GMID and UCID via the Socialize SDK Config endpoint.
        
        Returns:
            Optional[Dict[str, str]]: A dictionary with 'gmid' and 'ucid' keys if successful; otherwise, None.
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
        Perform login to Gigya using the provided email and password.
        
        Args:
            email (str): The user's email address.
            password (str): The user's password.
            gmid (str): The GMID retrieved from _get_ids.
            ucid (str): The UCID retrieved from _get_ids.
        
        Returns:
            LoginResponse: A dictionary containing session token, session secret, UID, signature timestamp, and UID signature.
        
        Raises:
            ValueError: If the login fails.
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
        Retrieve a JWT token from Gigya using the accounts.getJWT endpoint.
        
        Args:
            user (LoginResponse): The login response obtained from _login.
            gmid (str): The GMID value.
            ucid (str): The UCID value.
        
        Returns:
            Optional[str]: The JWT token if successful; otherwise, None.
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
        Refresh the control token using the id.api.bose.io endpoint.

        If access_token and refresh_token are not provided, the previously stored tokens are used.

        Args:
            access_token (Optional[str]): Existing access token.
            refresh_token (Optional[str]): Existing refresh token.

        Returns:
            ControlToken: A dictionary containing the new access token, refresh token, and Bose person ID.

        Raises:
            ValueError: If no control token is stored or required tokens are missing.
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

        Either provide:
            - gigya_jwt, signature_timestamp, uid, and uid_signature, or
            - access_token and refresh_token.

        Args:
            gigya_jwt (Optional[str]): JWT token from Gigya.
            signature_timestamp (Optional[str]): Signature timestamp.
            uid (Optional[str]): User ID.
            uid_signature (Optional[str]): UID signature.
            access_token (Optional[str]): Existing access token.
            refresh_token (Optional[str]): Existing refresh token.

        Returns:
            Optional[RawControlToken]: The fetched token if successful, otherwise None.
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
        Check if the given token is still valid by decoding it without verifying the signature.

        Args:
            token (str): The JWT token to validate.

        Returns:
            bool: True if the token has not expired, False otherwise.
        """
        try:
            decoded: Dict[str, Any] = jwt.decode(token, options={"verify_signature": False})
            exp: int = decoded.get("exp", 0)
            valid: bool = exp > int(time.time())
            if self._control_token is None:
                self._control_token = {"access_token": token}
            else:
                self._control_token["access_token"] = token
            return valid
        except Exception:
            return False

    def getControlToken(self, email: Optional[str] = None, password: Optional[str] = None, forceNew: bool = False) -> ControlToken:
        """
        Obtain the control token for accessing the local speaker API.

        If a token is already stored and valid, it is returned (unless forceNew is True). Otherwise, the
        token is retrieved by logging in and fetching keys from the Bose API.

        Args:
            email (Optional[str]): User's email address.
            password (Optional[str]): User's password.
            forceNew (bool): If True, force retrieval of a new token even if one is stored.

        Returns:
            ControlToken: A dictionary containing the access token, refresh token, and Bose person ID.

        Raises:
            ValueError: If email and password are not provided for the initial call or if token retrieval fails.
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

        Args:
            gwid (str): The product (or device) identifier.

        Returns:
            Optional[BoseApiProduct]: An instance of BoseApiProduct populated with the response data,
            or None if the fetch fails.
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