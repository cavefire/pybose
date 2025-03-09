# test_pybose.BoseAuth.py

import json
import time
import jwt
import pytest
import requests
from unittest.mock import patch, MagicMock

# Adjust the import below to match the module name where BoseAuth is defined.
from pybose.BoseAuth import BoseAuth, ControlToken

# --- Tests for _get_ids ---
def test_get_ids_success():
    auth = BoseAuth()
    dummy_response = {
        "ids": {
            "gmid": "test_gmid",
            "ucid": "test_ucid"
        }
    }
    with patch('pybose.BoseAuth.requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_response
        mock_post.return_value = mock_resp
        ids = auth._get_ids()
        assert ids == {"gmid": "test_gmid", "ucid": "test_ucid"}

def test_get_ids_failure():
    auth = BoseAuth()
    with patch('pybose.BoseAuth.requests.post', side_effect=Exception("Test error")):
        ids = auth._get_ids()
        assert ids is None

# --- Tests for _login ---
def test_login_success():
    auth = BoseAuth()
    dummy_json = {
        "sessionInfo": {
            "sessionToken": "test_token",
            "sessionSecret": "test_secret"
        },
        "userInfo": {
            "UID": "test_uid",
            "signatureTimestamp": "123456789",
            "UIDSignature": "test_uid_sig"
        }
    }
    with patch('pybose.BoseAuth.requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = dummy_json
        mock_post.return_value = mock_resp
        login_response = auth._login("test@example.com", "password", "test_gmid", "test_ucid")
        expected = {
            "session_token": "test_token",
            "session_secret": "test_secret",
            "uid": "test_uid",
            "signatureTimestamp": "123456789",
            "UIDSignature": "test_uid_sig"
        }
        assert login_response == expected

def test_login_failure():
    auth = BoseAuth()
    with patch('pybose.BoseAuth.requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Error"
        mock_post.return_value = mock_resp
        with pytest.raises(ValueError):
            auth._login("test@example.com", "password", "test_gmid", "test_ucid")

# --- Tests for _get_jwt ---
def test_get_jwt_success():
    auth = BoseAuth()
    dummy_login_response = {
        "session_token": "test_session_token",
        "session_secret": "test_session_secret",
        "uid": "test_uid",
        "signatureTimestamp": "123456789",
        "UIDSignature": "test_uid_sig"
    }
    dummy_jwt_response = {"id_token": "test_id_token"}
    # Patch GSRequest and SigUtils along with requests.post
    with patch('pybose.BoseAuth.GSRequest') as mock_gsrequest, \
         patch('pybose.BoseAuth.SigUtils') as mock_sigutils, \
         patch('pybose.BoseAuth.requests.post') as mock_post:
        instance = mock_gsrequest.return_value
        instance.calcOAuth1BaseString.return_value = "dummy_base_string"
        mock_sigutils.calcSignature.return_value = "dummy_sig"
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_jwt_response
        mock_post.return_value = mock_resp
        token = auth._get_jwt(dummy_login_response, "test_gmid", "test_ucid")
        assert token == "test_id_token"

def test_get_jwt_failure():
    auth = BoseAuth()
    dummy_login_response = {
        "session_token": "test_session_token",
        "session_secret": "test_session_secret",
        "uid": "test_uid",
        "signatureTimestamp": "123456789",
        "UIDSignature": "test_uid_sig"
    }
    with patch('pybose.BoseAuth.GSRequest') as mock_gsrequest, \
         patch('pybose.BoseAuth.SigUtils') as mock_sigutils, \
         patch('pybose.BoseAuth.requests.post', side_effect=Exception("Test error")):
        instance = mock_gsrequest.return_value
        instance.calcOAuth1BaseString.return_value = "dummy_base_string"
        mock_sigutils.calcSignature.return_value = "dummy_sig"
        token = auth._get_jwt(dummy_login_response, "test_gmid", "test_ucid")
        assert token is None

# --- Tests for do_token_refresh ---
def test_do_token_refresh_success():
    auth = BoseAuth()
    # Set up an initial control token.
    auth._control_token = {"access_token": "old_token", "refresh_token": "old_refresh"}
    new_token = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person123"}
    with patch.object(auth, '_fetch_keys', return_value=new_token):
        token = auth.do_token_refresh()
        expected = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
            "bose_person_id": "person123"
        }
        assert token == expected

def test_do_token_refresh_no_token():
    auth = BoseAuth()
    auth._control_token = None
    with pytest.raises(ValueError):
        auth.do_token_refresh()

# --- Tests for _fetch_keys ---
def test_fetch_keys_with_refresh_token():
    auth = BoseAuth()
    dummy_response = {"access_token": "refreshed_token", "refresh_token": "refreshed_refresh", "bosePersonID": "person456"}
    with patch('pybose.BoseAuth.requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_response
        mock_post.return_value = mock_resp
        result = auth._fetch_keys(access_token="token", refresh_token="refresh")
        assert result == dummy_response

def test_fetch_keys_with_gigya_jwt():
    auth = BoseAuth()
    dummy_response = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person789"}
    with patch('pybose.BoseAuth.requests.post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_response
        mock_post.return_value = mock_resp
        result = auth._fetch_keys(gigya_jwt="gigya_jwt", signature_timestamp="ts", uid="uid", uid_signature="uid_sig")
        assert result == dummy_response

def test_fetch_keys_failure():
    auth = BoseAuth()
    with patch('pybose.BoseAuth.requests.post', side_effect=Exception("Test error")):
        result = auth._fetch_keys(access_token="token", refresh_token="refresh")
        assert result is None

# --- Tests for is_token_valid ---
def test_is_token_valid():
    auth = BoseAuth()
    future_time = int(time.time()) + 60
    token_payload = {"exp": future_time}
    # Using 'none' algorithm so we don't require a key
    token = jwt.encode(token_payload, key="", algorithm="none")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    valid = auth.is_token_valid(token)
    assert valid is True
    # _control_token should be updated with the token.
    assert auth._control_token.get("access_token") == token

def test_is_token_invalid():
    auth = BoseAuth()
    past_time = int(time.time()) - 60
    token_payload = {"exp": past_time}
    token = jwt.encode(token_payload, key="", algorithm="none")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    valid = auth.is_token_valid(token)
    assert valid is False

# --- Tests for getControlToken ---
def test_get_control_token_new(monkeypatch):
    auth = BoseAuth()
    # Pre-set email and password.
    auth._email = "test@example.com"
    auth._password = "password"
    # Dummy return values for the chained methods.
    dummy_ids = {"gmid": "test_gmid", "ucid": "test_ucid"}
    dummy_login = {
        "session_token": "token",
        "session_secret": "secret",
        "uid": "uid",
        "signatureTimestamp": "ts",
        "UIDSignature": "uid_sig"
    }
    dummy_jwt = "dummy_jwt"
    dummy_fetch = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person001"}
    monkeypatch.setattr(auth, '_get_ids', lambda: dummy_ids)
    monkeypatch.setattr(auth, '_login', lambda email, pwd, gmid, ucid: dummy_login)
    monkeypatch.setattr(auth, '_get_jwt', lambda user, gmid, ucid: dummy_jwt)
    monkeypatch.setattr(auth, '_fetch_keys', lambda gigya_jwt, ts, uid, uid_sig: dummy_fetch)
    token = auth.getControlToken()
    expected = {"access_token": "new_token", "refresh_token": "new_refresh", "bose_person_id": "person001"}
    assert token == expected

# --- Tests for fetchProductInformation ---
def test_fetch_product_information():
    auth = BoseAuth()
    # Set a dummy control token so that the header can be built.
    auth._control_token = {"access_token": "test_access_token"}
    dummy_response = {"some_field": "some_value"}
    with patch('pybose.BoseAuth.requests.get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_response
        mock_get.return_value = mock_resp
        # Patch BoseApiProduct so that it returns the dictionary passed to it.
        with patch('pybose.BoseAuth.BoseApiProduct', side_effect=lambda **kwargs: kwargs):
            product_info = auth.fetchProductInformation("gwid123")
            assert product_info == dummy_response