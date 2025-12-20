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
import jwt
import hashlib
import base64
import secrets
import re
from typing import TypedDict, Optional, Dict, Any, cast
from urllib.parse import urlparse, parse_qs

from .BoseCloudResponse import BoseApiProduct

# --- API Types ---


class AzureADB2CTokenResponse(TypedDict):
    """
    Represents the response from Azure AD B2C token endpoint.

    Attributes:
        access_token (str): The access token.
        id_token (str): The ID token.
        token_type (str): The token type.
        expires_in (int): Token expiry time in seconds.
        refresh_token (str): The refresh token.
        scope (str): The token scope.
    """

    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    scope: str


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


# --- BoseAuth Class ---


class BoseAuth:
    """
    A class to interact with the BOSE online API for obtaining control tokens.

    This class uses Azure AD B2C authentication to obtain a JWT control token, which is used
    to control a local Bose speaker. It also provides methods to refresh tokens and to fetch
    product information from the BOSE API.

    Attributes:
        BOSE_API_KEY (str): Public API key for the BOSE API.
    """

    BOSE_API_KEY: str = "67616C617061676F732D70726F642D6D61647269642D696F73"

    def __init__(self) -> None:
        """
        Initialize a new BoseAuth instance.

        The control token, email, and password are initially unset.
        """
        self._control_token: Optional[RawControlToken] = None
        self._azure_refresh_token: Optional[str] = None
        self._email: Optional[str] = None
        self._password: Optional[str] = None
        self._session: requests.Session = requests.Session()

    def set_access_token(
        self, access_token: str, refresh_token: str, bose_person_id: str
    ) -> None:
        """
        Set the access token and refresh token.

        Args:
            access_token (str): The access token.
            refresh_token (str): The refresh token.
            bose_person_id (str): The Bose person ID.
        """
        self._control_token = cast(
            RawControlToken,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "bosePersonID": bose_person_id,
                "expires_in": 0,
                "scope": "",
                "token_type": "Bearer",
            },
        )

    def set_azure_refresh_token(self, azure_refresh_token: str) -> None:
        """
        Set the Azure AD B2C refresh token.

        This token is required for refreshing the Bose access tokens.

        Args:
            azure_refresh_token (str): The Azure AD B2C refresh token.
        """
        self._azure_refresh_token = azure_refresh_token

    def get_azure_refresh_token(self) -> Optional[str]:
        """
        Get the Azure AD B2C refresh token.

        Returns:
            Optional[str]: The Azure AD B2C refresh token if available, otherwise None.
        """
        return self._azure_refresh_token

    def _generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge"""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
            "utf-8"
        )
        code_verifier = code_verifier.replace("=", "")

        code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
        code_challenge = code_challenge.replace("=", "")

        return code_verifier, code_challenge

    def _extract_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML response"""
        patterns = [
            r'x-ms-cpim-csrf["\s]*[:=]["\s]*([^";\s]+)',
            r'"csrf"["\s]*:["\s]*"([^"]+)"',
            r'csrf_token["\s]*[:=]["\s]*"?([^";\s]+)"?',
            r'X-CSRF-TOKEN["\s]*[:=]["\s]*"?([^";\s]+)"?',
        ]

        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                logging.debug(f"Found CSRF token with pattern: {pattern}")
                return match.group(1)

        # Try to extract from cookies
        for cookie in self._session.cookies:
            if "csrf" in cookie.name.lower():
                logging.debug(f"Found CSRF token in cookie: {cookie.name}")
                return cookie.value

        logging.debug("No CSRF token found")
        return None

    def _extract_tx_param(self, url_or_html: str) -> Optional[str]:
        """Extract tx parameter from URL or HTML"""
        patterns = [
            r'[?&]tx=([^&"\']+)',
            r'"tx"["\s]*:["\s]*"([^"]+)"',
            r'StateProperties=([^&"\']+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, url_or_html)
            if match:
                logging.debug(f"Found tx param with pattern: {pattern}")
                return match.group(1)

        logging.debug("No tx parameter found")
        return None

    def _perform_azure_login(
        self, email: str, password: str
    ) -> Optional[AzureADB2CTokenResponse]:
        """
        Perform Azure AD B2C authentication flow.

        Args:
            email (str): User's email address.
            password (str): User's password.

        Returns:
            Optional[AzureADB2CTokenResponse]: Azure AD B2C tokens if successful, None otherwise.
        """
        # Clear session cookies to ensure clean state for new login
        self._session.cookies.clear()

        # Configuration - using mobile app flow for Bose API compatibility
        base_url = "https://myboseid.bose.com"
        tenant = "boseprodb2c.onmicrosoft.com"
        policy = "B2C_1A_MBI_SUSI"
        client_id = "e284648d-3009-47eb-8e74-670c5330ae54"
        redirect_uri = "bosemusic://auth/callback"
        scope = f"openid email profile offline_access {client_id}"

        # Generate PKCE
        code_verifier, code_challenge = self._generate_pkce()

        logging.debug("Starting Azure AD B2C authentication flow")

        # Step 1: Initial authorization request
        auth_params = {
            "p": policy,
            "response_type": "code",
            "client_id": client_id,
            "scope": scope,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
            "redirect_uri": redirect_uri,
            "ui_locales": "de-de",
        }

        auth_url = f"{base_url}/{tenant}/oauth2/v2.0/authorize"

        try:
            response = self._session.get(
                auth_url, params=auth_params, allow_redirects=True
            )

            if response.status_code != 200:
                logging.error(f"Authorization request failed: {response.status_code}")
                return None

            # Extract CSRF token and tx parameter
            csrf_token = self._extract_csrf_token(response.text)
            tx_param = self._extract_tx_param(response.text) or self._extract_tx_param(
                response.url
            )

            if not csrf_token or not tx_param:
                logging.error("Failed to extract CSRF token or tx parameter")
                return None

            logging.debug(f"CSRF Token: {csrf_token[:50]}...")
            logging.debug(f"TX Parameter: {tx_param[:50]}...")

            # Step 2: Submit email
            email_url = f"{base_url}/{tenant}/{policy}/SelfAsserted"
            email_params = {"tx": tx_param, "p": policy}
            email_data = {"request_type": "RESPONSE", "email": email}
            email_headers = {
                "X-CSRF-TOKEN": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": base_url,
                "Referer": response.url,
            }

            response = self._session.post(
                email_url, params=email_params, data=email_data, headers=email_headers
            )

            if response.status_code != 200:
                logging.error(f"Email submission failed: {response.status_code}")
                return None

            logging.debug("Email submitted successfully")

            # Step 3: Confirm email page
            confirm_url = (
                f"{base_url}/{tenant}/{policy}/api/CombinedSigninAndSignup/confirmed"
            )
            confirm_params = {
                "rememberMe": "false",
                "csrf_token": csrf_token,
                "tx": tx_param,
                "p": policy,
                "diags": json.dumps(
                    {
                        "pageViewId": "test",
                        "pageId": "CombinedSigninAndSignup",
                        "trace": [],
                    }
                ),
            }

            response = self._session.get(confirm_url, params=confirm_params)

            if response.status_code != 200:
                logging.error(f"Confirmation page failed: {response.status_code}")
                return None

            # Extract updated CSRF token
            csrf_token = self._extract_csrf_token(response.text) or csrf_token
            tx_param = self._extract_tx_param(response.text) or tx_param

            # Step 4: Submit password
            password_url = f"{base_url}/{tenant}/{policy}/SelfAsserted"
            password_params = {"tx": tx_param, "p": policy}
            password_data = {
                "readonlyEmail": email,
                "password": password,
                "request_type": "RESPONSE",
            }
            password_headers = {
                "X-CSRF-TOKEN": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": base_url,
                "Referer": response.url,
            }

            response = self._session.post(
                password_url,
                params=password_params,
                data=password_data,
                headers=password_headers,
            )

            if response.status_code != 200:
                logging.error(f"Password submission failed: {response.status_code}")
                return None

            logging.debug("Password submitted successfully")

            # Step 5: Confirm password page (this should redirect with authorization code)
            confirm2_url = f"{base_url}/{tenant}/{policy}/api/SelfAsserted/confirmed"
            confirm2_params = {
                "csrf_token": csrf_token,
                "tx": tx_param,
                "p": policy,
                "diags": json.dumps(
                    {"pageViewId": "test2", "pageId": "SelfAsserted", "trace": []}
                ),
            }

            response = self._session.get(
                confirm2_url, params=confirm2_params, allow_redirects=False
            )

            # Extract authorization code from redirect
            if response.status_code == 302:
                location = response.headers.get("Location", "")
                parsed = urlparse(location)
                query_params = parse_qs(parsed.query)
                auth_code = query_params.get("code", [None])[0]

                if not auth_code:
                    logging.error("No authorization code in redirect")
                    return None

                logging.debug(f"Authorization code received: {auth_code[:50]}...")
            else:
                logging.error(f"Expected redirect, got: {response.status_code}")
                return None

            # Step 6: Exchange code for tokens
            token_url = f"{base_url}/{tenant}/oauth2/v2.0/token"
            token_params = {"p": policy}
            token_data = {
                "client_id": client_id,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "scope": scope,
                "redirect_uri": redirect_uri,
                "code": auth_code,
            }
            token_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://www.bose.de",
                "Referer": "https://www.bose.de/",
            }

            response = self._session.post(
                token_url,
                params=token_params,
                data=token_data,
                headers=token_headers,
                allow_redirects=False,
            )

            if response.status_code != 200:
                logging.error(f"Token exchange failed: {response.status_code}")
                logging.error(f"Response: {response.text}")
                return None

            tokens: AzureADB2CTokenResponse = cast(
                AzureADB2CTokenResponse, response.json()
            )
            logging.debug("Azure AD B2C authentication successful")
            return tokens

        except Exception as e:
            logging.error(f"Error during Azure AD B2C authentication: {e}")
            return None

    def _exchange_id_token_for_bose_tokens(
        self, id_token: str
    ) -> Optional[RawControlToken]:
        """
        Exchange Azure AD B2C id_token for Bose internal tokens.

        Args:
            id_token (str): The Azure AD B2C id_token.

        Returns:
            Optional[RawControlToken]: The Bose internal tokens if successful, None otherwise.
        """
        bose_api_url = (
            "https://id.api.bose.io/id-jwt-core/idps/aad/B2C_1A_MBI_SUSI/token"
        )
        bose_client_id = "e284648d-3009-47eb-8e74-670c5330ae54"

        bose_payload = {
            "grant_type": "id_token",
            "id_token": id_token,
            "client_id": bose_client_id,
            "scope": f"openid email profile offline_access {bose_client_id}",
        }

        bose_headers = {
            "Content-Type": "application/json",
            "X-ApiKey": self.BOSE_API_KEY,
            "X-Api-Version": "1",
            "X-Software-Version": "1",
            "X-Library-Version": "1",
            "User-Agent": "Bose/37362 CFNetwork/3860.200.71 Darwin/25.1.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

        try:
            response = self._session.post(
                bose_api_url, json=bose_payload, headers=bose_headers
            )

            if response.status_code not in [200, 201]:
                logging.error(f"Bose token exchange failed: {response.status_code}")
                logging.error(f"Response: {response.text}")
                return None

            bose_tokens: IDJwtCoreTokenResponse = cast(
                IDJwtCoreTokenResponse, response.json()
            )
            logging.debug("Bose token exchange successful")
            return bose_tokens

        except Exception as e:
            logging.error(f"Error exchanging id_token for Bose tokens: {e}")
            return None

    def do_token_refresh(
        self, access_token: Optional[str] = None, refresh_token: Optional[str] = None
    ) -> ControlToken:
        """
        Refresh the control token using the Azure AD B2C refresh flow.

        If access_token and refresh_token are not provided, the previously stored tokens are used.
        Note: The refresh_token parameter is ignored as we use the stored Azure refresh token.

        Args:
            access_token (Optional[str]): Existing access token (ignored, kept for compatibility).
            refresh_token (Optional[str]): Existing refresh token (ignored, kept for compatibility).

        Returns:
            ControlToken: A dictionary containing the new access token, refresh token, and Bose person ID.

        Raises:
            ValueError: If no control token is stored or required tokens are missing.
        """
        if self._control_token is None:
            raise ValueError("No control token stored to refresh.")

        if self._azure_refresh_token is None:
            raise ValueError("No Azure refresh token available. Please login again.")

        # First, refresh Azure AD B2C tokens using the stored Azure refresh token
        azure_tokens = self._refresh_azure_tokens(self._azure_refresh_token)
        if azure_tokens is None:
            raise ValueError("Failed to refresh Azure AD B2C tokens")

        # Update stored Azure refresh token
        self._azure_refresh_token = azure_tokens.get("refresh_token")

        # Then exchange the new id_token for Bose tokens
        bose_tokens = self._exchange_id_token_for_bose_tokens(azure_tokens["id_token"])
        if bose_tokens is None:
            raise ValueError(
                "Failed to exchange id_token for Bose tokens after refresh"
            )

        self._control_token = bose_tokens
        return {
            "access_token": bose_tokens.get("access_token", ""),
            "refresh_token": bose_tokens.get("refresh_token", ""),
            "bose_person_id": bose_tokens.get("bosePersonID", ""),
        }

    def _refresh_azure_tokens(
        self, refresh_token: str
    ) -> Optional[AzureADB2CTokenResponse]:
        """
        Refresh Azure AD B2C tokens using a refresh token.

        Args:
            refresh_token (str): The Azure AD B2C refresh token.

        Returns:
            Optional[AzureADB2CTokenResponse]: The refreshed Azure tokens if successful, otherwise None.
        """
        base_url = "https://myboseid.bose.com"
        tenant = "boseprodb2c.onmicrosoft.com"
        policy = "B2C_1A_MBI_SUSI"
        client_id = "e284648d-3009-47eb-8e74-670c5330ae54"

        token_url = f"{base_url}/{tenant}/{policy}/oauth2/v2.0/token"

        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": "Bose/37362 CFNetwork/3860.200.71 Darwin/25.1.0",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        }

        data = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "grant_type": "refresh_token",
        }

        try:
            response = self._session.post(token_url, headers=headers, data=data)
            if response.status_code != 200:
                logging.error(f"Azure token refresh failed: {response.status_code}")
                logging.error(f"Response: {response.text}")
                return None

            response_json: Dict[str, Any] = response.json()
            logging.debug("Azure AD B2C token refresh successful")
            azure_tokens: AzureADB2CTokenResponse = cast(
                AzureADB2CTokenResponse, response_json
            )
            return azure_tokens
        except Exception as e:
            logging.error(f"Error refreshing Azure tokens: {e}")
            return None

    def get_token_validity_time(self, token: Optional[str] = None) -> int:
        """
        Get the validity time of the given token.

        Args:
            token (Optional[str]): The JWT token to check.

        Returns:
            int: The time until the token expires in seconds.
        """

        if token is None:
            if self._control_token:
                token = self._control_token.get("access_token")
        if token is None:
            return 0

        try:
            decoded: Dict[str, Any] = jwt.decode(
                token, options={"verify_signature": False}
            )
            exp: int = decoded.get("exp", 0)
            return exp - int(time.time())
        except Exception as e:
            logging.error(f"Error decoding token: {e}")
            return 0

    def is_token_valid(self, token: Optional[str] = None) -> bool:
        """
        Check if the given token is still valid by decoding it without verifying the signature.

        Args:
            token (Optional[str]): The JWT token to validate.

        Returns:
            bool: True if the token has not expired, False otherwise.
        """

        if token is None:
            if self._control_token:
                token = self._control_token.get("access_token")
        if token is None:
            return False

        try:
            decoded: Dict[str, Any] = jwt.decode(
                token, options={"verify_signature": False}
            )
            exp: int = decoded.get("exp", 0)
            valid: bool = exp > int(time.time())
            if self._control_token is None and token:
                self._control_token = cast(
                    RawControlToken,
                    {
                        "access_token": token,
                        "bosePersonID": "",
                        "expires_in": 0,
                        "refresh_token": "",
                        "scope": "",
                        "token_type": "Bearer",
                    },
                )
            elif self._control_token and token:
                self._control_token["access_token"] = token
            return valid
        except Exception:
            return False

    def getCachedToken(self) -> Optional[ControlToken]:
        """
        Get the cached control token.

        Returns:
            Optional[ControlToken]: The cached control token if available, otherwise None.
        """
        if self._control_token is None:
            return None
        return {
            "access_token": self._control_token.get("access_token", ""),
            "refresh_token": self._control_token.get("refresh_token", ""),
            "bose_person_id": self._control_token.get("bosePersonID", ""),
        }

    def getControlToken(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
        forceNew: bool = False,
    ) -> ControlToken:
        """
        Obtain the control token for accessing the local speaker API.

        If a token is already stored and valid, it is returned (unless forceNew is True). Otherwise, the
        token is retrieved by logging in via Azure AD B2C and exchanging for Bose tokens.

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
            if access_token and self.is_token_valid():
                return {
                    "access_token": self._control_token.get("access_token", ""),
                    "refresh_token": self._control_token.get("refresh_token", ""),
                    "bose_person_id": self._control_token.get("bosePersonID", ""),
                }
            else:
                logging.debug("Token is expired. Trying to refresh token")
                # Try to refresh the token
                try:
                    return self.do_token_refresh()
                except Exception as e:
                    logging.debug(f"Token refresh failed: {e}. Will try full login.")

        if email is not None:
            self._email = email
        if password is not None:
            self._password = password

        if self._email is None or self._password is None:
            raise ValueError("Email and password are required for the first call!")

        # Perform Azure AD B2C login
        azure_tokens = self._perform_azure_login(self._email, self._password)
        if azure_tokens is None:
            raise ValueError("Azure AD B2C login failed")

        # Store Azure refresh token for later use
        self._azure_refresh_token = azure_tokens.get("refresh_token")

        # Exchange id_token for Bose tokens
        bose_tokens = self._exchange_id_token_for_bose_tokens(azure_tokens["id_token"])
        if bose_tokens is None:
            raise ValueError("Failed to exchange id_token for Bose tokens")

        self._control_token = bose_tokens
        return {
            "access_token": bose_tokens.get("access_token", ""),
            "refresh_token": bose_tokens.get("refresh_token", ""),
            "bose_person_id": bose_tokens.get("bosePersonID", ""),
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
            "X-User-Token": self._control_token.get("access_token")
            if self._control_token
            else "",
        }
        try:
            response_json: Dict[str, Any] = self._session.get(
                url, headers=headers
            ).json()
            logging.debug(f"product info: {json.dumps(response_json, indent=4)}")
        except Exception as e:
            logging.error(f"Error fetching product information: {e}")
            return None
        product_resp: UsersApiBoseProductResponse = cast(
            UsersApiBoseProductResponse, response_json
        )
        return BoseApiProduct(**product_resp)
