# test_pybose.BoseAuth.py

import json
import time
import jwt
import pytest
import requests
from unittest.mock import patch, MagicMock

# Adjust the import below to match the module name where BoseAuth is defined.
from pybose.BoseAuth import BoseAuth, ControlToken

# --- Tests for PKCE generation ---
def test_generate_pkce():
    auth = BoseAuth()
    code_verifier, code_challenge = auth._generate_pkce()
    assert code_verifier is not None
    assert code_challenge is not None
    assert len(code_verifier) > 0
    assert len(code_challenge) > 0
    assert '=' not in code_verifier  # URL-safe, no padding
    assert '=' not in code_challenge  # URL-safe, no padding

# --- Tests for CSRF token extraction ---
def test_extract_csrf_token_from_html():
    auth = BoseAuth()
    html_content = 'var SETTINGS = {"csrf": "test_csrf_token_123"};'
    csrf_token = auth._extract_csrf_token(html_content)
    assert csrf_token == "test_csrf_token_123"

def test_extract_csrf_token_not_found():
    auth = BoseAuth()
    html_content = '<html><body>No CSRF token here</body></html>'
    csrf_token = auth._extract_csrf_token(html_content)
    assert csrf_token is None

# --- Tests for tx parameter extraction ---
def test_extract_tx_param_from_url():
    auth = BoseAuth()
    url = "https://example.com/authorize?tx=StateProperties123&other=param"
    tx_param = auth._extract_tx_param(url)
    assert tx_param == "StateProperties123"

def test_extract_tx_param_not_found():
    auth = BoseAuth()
    url = "https://example.com/authorize?other=param"
    tx_param = auth._extract_tx_param(url)
    assert tx_param is None

# --- Tests for get_token_validity_time ---
def test_get_token_validity_time_valid_token():
    auth = BoseAuth()
    future_time = int(time.time()) + 3600
    token = jwt.encode({"exp": future_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "refresh", "person123")
    validity = auth.get_token_validity_time()
    assert validity > 3500  # Should be close to 3600

def test_get_token_validity_time_expired_token():
    auth = BoseAuth()
    past_time = int(time.time()) - 3600
    token = jwt.encode({"exp": past_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "refresh", "person123")
    validity = auth.get_token_validity_time()
    assert validity < 0

def test_get_token_validity_time_no_token():
    auth = BoseAuth()
    validity = auth.get_token_validity_time()
    assert validity == 0

def test_get_token_validity_time_invalid_token():
    auth = BoseAuth()
    auth.set_access_token("invalid_token", "refresh", "person123")
    validity = auth.get_token_validity_time()
    assert validity == 0

# --- Tests for is_token_valid edge cases ---
def test_is_token_valid_no_access_token():
    auth = BoseAuth()
    auth._control_token = ControlToken(access_token=None, refresh_token="refresh", bose_person_id="person123")
    assert auth.is_token_valid() is False

def test_is_token_valid_expired_token_decode_error():
    auth = BoseAuth()
    auth.set_access_token("malformed.jwt.token", "refresh", "person123")
    assert auth.is_token_valid() is False

# --- Tests for getCachedToken ---
def test_get_cached_token_valid():
    auth = BoseAuth()
    future_time = int(time.time()) + 3600
    token = jwt.encode({"exp": future_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "refresh", "person123")
    cached = auth.getCachedToken()
    assert cached["access_token"] == token
    assert cached["refresh_token"] == "refresh"
    assert cached["bose_person_id"] == "person123"

def test_get_cached_token_expired():
    auth = BoseAuth()
    past_time = int(time.time()) - 3600
    token = jwt.encode({"exp": past_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "refresh", "person123")
    cached = auth.getCachedToken()
    # getCachedToken returns the token regardless of expiration
    assert cached is not None
    assert cached["access_token"] == token

# --- Tests for getControlToken edge cases ---
def test_get_control_token_with_valid_cached_token():
    auth = BoseAuth()
    future_time = int(time.time()) + 3600
    token = jwt.encode({"exp": future_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "refresh_token", "person123")
    auth._azure_refresh_token = "azure_refresh"
    
    # Should return cached token without calling login
    result = auth.getControlToken("user@example.com", "password")
    assert result["access_token"] == token
    assert result["refresh_token"] == "refresh_token"
    assert result["bose_person_id"] == "person123"

def test_get_control_token_with_expired_token_refresh():
    auth = BoseAuth()
    past_time = int(time.time()) - 3600
    token = jwt.encode({"exp": past_time}, "secret", algorithm="HS256")
    auth.set_access_token(token, "old_refresh", "person123")
    auth._azure_refresh_token = "azure_refresh"
    
    azure_tokens = {"access_token": "azure_access", "id_token": "azure_id_token", "refresh_token": "new_azure_refresh", "token_type": "Bearer", "expires_in": 300, "scope": "openid"}
    new_bose_tokens = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person456", "expires_in": 3600, "scope": "openid", "token_type": "Bearer"}
    
    with patch.object(auth, '_refresh_azure_tokens', return_value=azure_tokens), \
         patch.object(auth, '_exchange_id_token_for_bose_tokens', return_value=new_bose_tokens):
        result = auth.getControlToken("user@example.com", "password")
        assert result["access_token"] == "new_token"
        assert result["refresh_token"] == "new_refresh"
        assert result["bose_person_id"] == "person456"

def test_get_control_token_new_login():
    auth = BoseAuth()
    
    azure_tokens = {"access_token": "azure_access", "id_token": "azure_id_token", "refresh_token": "azure_refresh", "token_type": "Bearer", "expires_in": 300, "scope": "openid"}
    bose_tokens = {"access_token": "bose_token", "refresh_token": "bose_refresh", "bosePersonID": "person123", "expires_in": 3600, "scope": "openid", "token_type": "Bearer"}
    
    with patch.object(auth, '_perform_azure_login', return_value=azure_tokens), \
         patch.object(auth, '_exchange_id_token_for_bose_tokens', return_value=bose_tokens):
        result = auth.getControlToken("user@example.com", "password")
        assert result["access_token"] == "bose_token"
        assert result["refresh_token"] == "bose_refresh"
        assert result["bose_person_id"] == "person123"
        assert auth._azure_refresh_token == "azure_refresh"

# --- Tests for do_token_refresh ---
def test_do_token_refresh_success():
    auth = BoseAuth()
    # Set up an initial control token and Azure refresh token
    auth.set_access_token("old_token", "old_refresh", "person123")
    auth._azure_refresh_token = "azure_refresh_token"
    azure_tokens = {"access_token": "azure_access", "id_token": "azure_id_token", "refresh_token": "new_azure_refresh", "token_type": "Bearer", "expires_in": 300, "scope": "openid"}
    new_bose_tokens = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person456", "expires_in": 3600, "scope": "openid", "token_type": "Bearer"}
    with patch.object(auth, '_refresh_azure_tokens', return_value=azure_tokens), \
         patch.object(auth, '_exchange_id_token_for_bose_tokens', return_value=new_bose_tokens):
        token = auth.do_token_refresh()
        expected = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
            "bose_person_id": "person456"
        }
        assert token == expected
        # Verify Azure refresh token was updated
        assert auth._azure_refresh_token == "new_azure_refresh"

def test_do_token_refresh_no_token():
    auth = BoseAuth()
    auth._control_token = None
    with pytest.raises(ValueError):
        auth.do_token_refresh()

# --- Tests for _refresh_azure_tokens ---
def test_refresh_azure_tokens_success():
    auth = BoseAuth()
    dummy_response = {"access_token": "azure_access", "id_token": "azure_id", "refresh_token": "refreshed_refresh", "token_type": "Bearer", "expires_in": 300, "scope": "openid"}
    with patch.object(auth._session, 'post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = dummy_response
        mock_post.return_value = mock_resp
        result = auth._refresh_azure_tokens(refresh_token="refresh")
        assert result == dummy_response

def test_refresh_azure_tokens_failure():
    auth = BoseAuth()
    with patch.object(auth._session, 'post', side_effect=Exception("Test error")):
        result = auth._refresh_azure_tokens(refresh_token="refresh")
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
    assert auth._control_token is not None
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
    dummy_azure_tokens = {"id_token": "test_id_token", "access_token": "azure_access", "refresh_token": "azure_refresh", "token_type": "Bearer", "expires_in": 3600, "scope": "openid"}
    dummy_bose_tokens = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person001", "expires_in": 3600, "scope": "openid", "token_type": "Bearer"}
    monkeypatch.setattr(auth, '_perform_azure_login', lambda email, pwd: dummy_azure_tokens)
    monkeypatch.setattr(auth, '_exchange_id_token_for_bose_tokens', lambda id_token: dummy_bose_tokens)
    token = auth.getControlToken()
    expected = {"access_token": "new_token", "refresh_token": "new_refresh", "bose_person_id": "person001"}
    assert token == expected

# --- Tests for fetchProductInformation ---
def test_fetch_product_information():
    auth = BoseAuth()
    # Set a dummy control token so that the header can be built.
    auth.set_access_token("test_access_token", "test_refresh_token", "person123")
    dummy_response = {"productID": "test_product", "productType": "speaker", "users": {}}
    with patch.object(auth._session, 'get') as mock_get:
        mock_resp = MagicMock()
        mock_resp.json.return_value = dummy_response
        mock_get.return_value = mock_resp
        # Patch BoseApiProduct so that it returns the dictionary passed to it.
        with patch('pybose.BoseAuth.BoseApiProduct', side_effect=lambda **kwargs: kwargs):
            result = auth.fetchProductInformation("test_gwid")
            assert result["productID"] == "test_product"

def test_fetch_product_information_error():
    auth = BoseAuth()
    auth.set_access_token("test_access_token", "test_refresh_token", "person123")
    with patch.object(auth._session, 'get') as mock_get:
        mock_get.side_effect = Exception("Network error")
        result = auth.fetchProductInformation("test_gwid")
        assert result is None

# --- Tests for _extract_csrf_token edge cases ---
def test_extract_csrf_token_from_cookie():
    auth = BoseAuth()
    # Simulate a cookie with csrf in the name
    from http.cookiejar import Cookie
    cookie = Cookie(
        version=0, name='x-csrf-token', value='cookie_csrf_123',
        port=None, port_specified=False,
        domain='example.com', domain_specified=False, domain_initial_dot=False,
        path='/', path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False
    )
    auth._session.cookies.set_cookie(cookie)
    
    html_without_csrf = '<html><body>No CSRF here</body></html>'
    csrf_token = auth._extract_csrf_token(html_without_csrf)
    assert csrf_token == 'cookie_csrf_123'

def test_extract_csrf_token_no_match():
    auth = BoseAuth()
    html_content = '<html><body>Nothing here</body></html>'
    csrf_token = auth._extract_csrf_token(html_content)
    assert csrf_token is None

def test_extract_tx_param_no_match():
    auth = BoseAuth()
    url = "https://example.com/page?other=value"
    tx_param = auth._extract_tx_param(url)
    assert tx_param is None

# --- Tests for _perform_azure_login with mocked responses ---
def test_perform_azure_login_authorization_failure():
    """Test _perform_azure_login when the initial authorization request fails"""
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get:
        # Return non-200 status code
        authorize_resp = MagicMock()
        authorize_resp.status_code = 400
        mock_get.return_value = authorize_resp
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

def test_perform_azure_login_missing_csrf():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get:
        # Return response without CSRF token
        authorize_resp = MagicMock()
        authorize_resp.text = '<html>No CSRF token</html>'
        authorize_resp.url = "https://login.bose.io"
        mock_get.return_value = authorize_resp
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

def test_perform_azure_login_missing_tx():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get, \
         patch.object(auth._session, 'post') as mock_post:
        
        # Step 1: Has CSRF but no tx parameter
        authorize_resp = MagicMock()
        authorize_resp.text = 'var SETTINGS = {"csrf": "csrf_token_123"};'
        authorize_resp.url = "https://login.bose.io"  # No tx parameter
        
        mock_get.return_value = authorize_resp
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

def test_perform_azure_login_network_error():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get:
        mock_get.side_effect = Exception("Network error")
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

def test_perform_azure_login_missing_auth_code():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get, \
         patch.object(auth._session, 'post') as mock_post:
        
        # Complete flow but redirect doesn't contain auth code
        authorize_resp = MagicMock()
        authorize_resp.text = 'var SETTINGS = {"csrf": "csrf_token_123"};'
        authorize_resp.url = "https://login.bose.io?tx=StateProperties_abc"
        
        confirm_resp = MagicMock()
        confirm_resp.status_code = 200
        confirm_resp.url = "https://login.bose.io/confirmed"
        
        confirmed_resp = MagicMock()
        confirmed_resp.text = 'StateProperties=StateProperties_def'
        confirmed_resp.url = "https://login.bose.io/confirmed"
        
        password_resp = MagicMock()
        password_resp.status_code = 200
        password_resp.url = "https://login.bose.io/password"
        
        password_page_resp = MagicMock()
        password_page_resp.text = '"tx":"StateProperties_ghi"'
        password_page_resp.url = "https://login.bose.io/password"
        
        # Redirect without code parameter
        submit_resp = MagicMock()
        submit_resp.status_code = 302
        submit_resp.headers = {'Location': 'bosemusic://oauth'}  # No code
        
        mock_get.side_effect = [authorize_resp, confirmed_resp, password_page_resp]
        mock_post.side_effect = [confirm_resp, password_resp, submit_resp]
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

def test_perform_azure_login_token_exchange_failure():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'get') as mock_get, \
         patch.object(auth._session, 'post') as mock_post:
        
        # Complete flow but token exchange fails
        authorize_resp = MagicMock()
        authorize_resp.text = 'var SETTINGS = {"csrf": "csrf_token_123"};'
        authorize_resp.url = "https://login.bose.io?tx=StateProperties_abc"
        
        confirm_resp = MagicMock()
        confirm_resp.status_code = 200
        
        confirmed_resp = MagicMock()
        confirmed_resp.text = 'StateProperties=StateProperties_def'
        
        password_resp = MagicMock()
        password_resp.status_code = 200
        
        password_page_resp = MagicMock()
        password_page_resp.text = '"tx":"StateProperties_ghi"'
        
        submit_resp = MagicMock()
        submit_resp.status_code = 302
        submit_resp.headers = {'Location': 'bosemusic://oauth?code=auth_code_123'}
        
        # Token exchange fails
        token_resp = MagicMock()
        token_resp.status_code = 400
        
        mock_get.side_effect = [authorize_resp, confirmed_resp, password_page_resp]
        mock_post.side_effect = [confirm_resp, password_resp, submit_resp, token_resp]
        
        result = auth._perform_azure_login("test@example.com", "password123")
        assert result is None

# --- Tests for _refresh_azure_tokens error handling ---
def test_refresh_azure_tokens_network_error():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'post') as mock_post:
        mock_post.side_effect = Exception("Network error")
        result = auth._refresh_azure_tokens("refresh_token")
        assert result is None

# --- Tests for _exchange_id_token_for_bose_tokens ---
def test_exchange_id_token_for_bose_tokens_success():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "access_token": "bose_access",
            "refresh_token": "bose_refresh",
            "bosePersonID": "person123",
            "expires_in": 28800,
            "token_type": "Bearer",
            "scope": "openid"
        }
        mock_post.return_value = mock_resp
        
        result = auth._exchange_id_token_for_bose_tokens("azure_id_token")
        
        assert result is not None
        assert result["access_token"] == "bose_access"
        assert result["bosePersonID"] == "person123"

def test_exchange_id_token_for_bose_tokens_failure():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'post') as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Invalid token"
        mock_post.return_value = mock_resp
        
        result = auth._exchange_id_token_for_bose_tokens("invalid_token")
        assert result is None

def test_exchange_id_token_for_bose_tokens_network_error():
    auth = BoseAuth()
    
    with patch.object(auth._session, 'post') as mock_post:
        mock_post.side_effect = Exception("Network error")
        
        result = auth._exchange_id_token_for_bose_tokens("azure_id_token")
        assert result is None

# --- Tests for getControlToken with expired token refresh attempt ---
def test_get_control_token_expired_token_refresh_exception():
    auth = BoseAuth()
    auth._email = "test@example.com"
    auth._password = "password"
    
    # Create an expired token
    import jwt
    import time
    expired_payload = {'exp': int(time.time()) - 3600, 'iat': int(time.time()) - 7200}
    expired_token = jwt.encode(expired_payload, 'secret', algorithm='HS256')
    
    auth._control_token = {
        "access_token": expired_token,
        "refresh_token": "refresh_token",
        "bosePersonID": "person123"
    }
    auth._azure_refresh_token = "azure_refresh"
    
    # Mock do_token_refresh to raise an exception
    with patch.object(auth, 'do_token_refresh') as mock_refresh, \
         patch.object(auth, '_perform_azure_login') as mock_login, \
         patch.object(auth, '_exchange_id_token_for_bose_tokens') as mock_exchange:
        
        mock_refresh.side_effect = Exception("Refresh failed")
        
        # Mock successful login flow after refresh fails
        mock_login.return_value = {"access_token": "new_azure", "id_token": "new_id", "refresh_token": "new_refresh"}
        mock_exchange.return_value = {"access_token": "new_token", "refresh_token": "new_refresh", "bosePersonID": "person123"}
        
        result = auth.getControlToken()
        
        assert result["access_token"] == "new_token"
        # Verify do_token_refresh was attempted
        mock_refresh.assert_called_once()
        # Verify fallback to login was used
        mock_login.assert_called_once()

# --- Tests for do_token_refresh error cases ---
def test_do_token_refresh_no_azure_refresh_token():
    auth = BoseAuth()
    # Set control token but not Azure refresh token
    auth._control_token = {"access_token": "token", "refresh_token": "refresh", "bosePersonID": "person123"}
    with pytest.raises(ValueError, match="No Azure refresh token available"):
        auth.do_token_refresh()

def test_do_token_refresh_refresh_failed():
    auth = BoseAuth()
    auth._control_token = {"access_token": "token", "refresh_token": "refresh", "bosePersonID": "person123"}
    auth._azure_refresh_token = "azure_refresh"
    
    with patch.object(auth, '_refresh_azure_tokens') as mock_refresh:
        mock_refresh.return_value = None  # Refresh fails
        
        with pytest.raises(ValueError, match="Failed to refresh Azure AD B2C tokens"):
            auth.do_token_refresh()

def test_do_token_refresh_exchange_failed():
    auth = BoseAuth()
    auth._control_token = {"access_token": "token", "refresh_token": "refresh", "bosePersonID": "person123"}
    auth._azure_refresh_token = "azure_refresh"
    
    azure_tokens = {"access_token": "new_azure", "id_token": "new_id", "refresh_token": "new_refresh"}
    
    with patch.object(auth, '_refresh_azure_tokens') as mock_refresh, \
         patch.object(auth, '_exchange_id_token_for_bose_tokens') as mock_exchange:
        mock_refresh.return_value = azure_tokens
        mock_exchange.return_value = None  # Exchange fails
        
        with pytest.raises(ValueError, match="Failed to exchange id_token for Bose tokens after refresh"):
            auth.do_token_refresh()