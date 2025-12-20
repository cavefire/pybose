import os
import time
import jwt
import pytest
from pybose.BoseAuth import BoseAuth

@pytest.fixture(scope="module")
def auth():
    """
    Returns an instance of BoseAuth.
    Requires BOSE_EMAIL and BOSE_PASSWORD environment variables.
    """
    email = os.environ.get("BOSE_EMAIL")
    password = os.environ.get("BOSE_PASSWORD")
    if not email or not password:
        pytest.skip("BOSE_EMAIL and BOSE_PASSWORD environment variables not set. Skipping integration tests.")
    return BoseAuth()

@pytest.fixture(scope="module")
def credentials():
    """
    Returns email and password from environment variables.
    """
    email = os.environ.get("BOSE_EMAIL")
    password = os.environ.get("BOSE_PASSWORD")
    if not email or not password:
        pytest.skip("BOSE_EMAIL and BOSE_PASSWORD environment variables not set. Skipping integration tests.")
    return email, password

@pytest.mark.integration
def test_azure_login_flow_integration(auth, credentials):
    """
    Test the complete Azure AD B2C login flow (_perform_azure_login).
    This validates the entire 6-step authentication process.
    """
    email, password = credentials
    
    # Perform Azure login
    azure_tokens = auth._perform_azure_login(email, password)
    
    assert azure_tokens is not None, "Azure login failed"
    assert "access_token" in azure_tokens, "Azure access_token missing"
    assert "id_token" in azure_tokens, "Azure id_token missing"
    assert "refresh_token" in azure_tokens, "Azure refresh_token missing"
    assert "token_type" in azure_tokens, "token_type missing"
    assert azure_tokens["token_type"] == "Bearer", "Invalid token type"
    
    # Validate the id_token is a valid JWT
    decoded = jwt.decode(azure_tokens["id_token"], options={"verify_signature": False})
    assert "exp" in decoded, "Expiration not found in id_token"
    assert decoded["exp"] > time.time(), "id_token is expired"

@pytest.mark.integration
def test_exchange_id_token_for_bose_tokens_integration(auth, credentials):
    """
    Test exchanging Azure AD B2C id_token for Bose access/refresh tokens.
    """
    email, password = credentials
    
    # First get Azure tokens
    azure_tokens = auth._perform_azure_login(email, password)
    assert azure_tokens is not None, "Azure login failed"
    
    # Exchange id_token for Bose tokens
    bose_tokens = auth._exchange_id_token_for_bose_tokens(azure_tokens["id_token"])
    
    assert bose_tokens is not None, "Failed to exchange id_token for Bose tokens"
    assert "access_token" in bose_tokens, "Bose access_token missing"
    assert "refresh_token" in bose_tokens, "Bose refresh_token missing"
    assert "bosePersonID" in bose_tokens, "bosePersonID missing"
    
    # Validate the access_token is a valid JWT
    decoded = jwt.decode(bose_tokens["access_token"], options={"verify_signature": False})
    assert "exp" in decoded, "Expiration not found in Bose access_token"
    assert "tokenName" in decoded, "tokenName not found in Bose access_token"
    assert decoded["tokenName"] == "access_token", "Invalid tokenName"

@pytest.mark.integration
def test_refresh_azure_tokens_integration(auth, credentials):
    """
    Test refreshing Azure AD B2C tokens using refresh_token.
    """
    email, password = credentials
    
    # First get initial Azure tokens
    initial_tokens = auth._perform_azure_login(email, password)
    assert initial_tokens is not None, "Azure login failed"
    
    # Store the refresh token
    refresh_token = initial_tokens["refresh_token"]
    
    # Refresh the Azure tokens
    refreshed_tokens = auth._refresh_azure_tokens(refresh_token)
    
    assert refreshed_tokens is not None, "Failed to refresh Azure tokens"
    assert "access_token" in refreshed_tokens, "Azure access_token missing"
    assert "id_token" in refreshed_tokens, "Azure id_token missing"
    assert "refresh_token" in refreshed_tokens, "Azure refresh_token missing"
    
    # Note: Azure AD B2C may return the same id_token if it hasn't expired yet
    # This is expected behavior, so we just verify the token exists and is valid
    decoded = jwt.decode(refreshed_tokens["id_token"], options={"verify_signature": False})
    assert decoded["exp"] > time.time(), "Refreshed id_token is expired"

@pytest.mark.integration
def test_get_control_token_integration(auth, credentials):
    """
    Test the complete token retrieval flow via getControlToken.
    This test verifies that a valid JWT is returned.
    """
    email, password = credentials
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    assert "access_token" in token, "Access token not found"
    assert "refresh_token" in token, "Refresh token not found"
    assert "bose_person_id" in token, "Bose person ID not found"
    
    # Verify the access_token is a valid JWT
    decoded = jwt.decode(token["access_token"], options={"verify_signature": False})
    assert "exp" in decoded, "Expiration not found in token"
    assert "tokenName" in decoded and decoded["tokenName"] == "access_token", "Token name not found or incorrect"
    assert decoded["exp"] > time.time(), "Token is expired"

@pytest.mark.integration
def test_get_control_token_cached_integration(auth, credentials):
    """
    Test that getControlToken returns cached token when valid.
    """
    email, password = credentials
    
    # First call - should perform login
    token1 = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token1 is not None, "Failed to retrieve control token"
    
    # Second call - should return cached token
    token2 = auth.getControlToken(email=email, password=password, forceNew=False)
    assert token2 is not None, "Failed to retrieve cached token"
    assert token2["access_token"] == token1["access_token"], "Cached token differs from original"
    assert token2["refresh_token"] == token1["refresh_token"], "Cached refresh token differs"

@pytest.mark.integration
def test_token_validity_time_integration(auth, credentials):
    """
    Test get_token_validity_time with real tokens.
    """
    email, password = credentials
    
    # Get a fresh token
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    
    # Check token validity time
    validity_seconds = auth.get_token_validity_time()
    assert validity_seconds > 0, "Token should be valid"
    # Bose tokens can be valid for up to 8 hours (28800 seconds)
    assert validity_seconds <= 28800, "Token validity should be less than 8 hours"

@pytest.mark.integration
def test_is_token_valid_integration(auth, credentials):
    """
    Test is_token_valid with real tokens.
    """
    email, password = credentials
    
    # Get a fresh token
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    
    # Token should be valid
    assert auth.is_token_valid() is True, "Fresh token should be valid"

@pytest.mark.integration
def test_refresh_token_integration(auth, credentials):
    """
    Test refreshing the access token using do_token_refresh.
    """
    email, password = credentials
    
    # Get initial token
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    
    # Store initial values
    initial_access = token["access_token"]
    initial_refresh = token["refresh_token"]
    
    # Refresh the token
    refreshed = auth.do_token_refresh()
    
    assert refreshed is not None, "Failed to refresh token"
    assert "access_token" in refreshed, "Access token not found"
    assert "refresh_token" in refreshed, "Refresh token not found"
    assert "bose_person_id" in refreshed, "Bose person ID not found"
    
    # Tokens should be different after refresh
    assert refreshed["access_token"] != initial_access, "Access token was not refreshed"
    assert refreshed["refresh_token"] != initial_refresh, "Refresh token was not refreshed"
    
    # New token should be valid
    decoded = jwt.decode(refreshed["access_token"], options={"verify_signature": False})
    assert decoded["exp"] > time.time(), "Refreshed token is expired"

@pytest.mark.integration
def test_get_cached_token_integration(auth, credentials):
    """
    Test getCachedToken returns the stored token.
    """
    email, password = credentials
    
    # Get a fresh token
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    
    # Get cached token
    cached = auth.getCachedToken()
    assert cached is not None, "Cached token should not be None"
    assert cached["access_token"] == token["access_token"], "Cached token differs"
    assert cached["bose_person_id"] == token["bose_person_id"], "Cached person ID differs"

@pytest.mark.integration
def test_fetch_product_information_integration(auth):
    """
    Test fetching product information using a valid gwid.
    Requires BOSE_GWID to be set as an environment variable.
    """
    gwid = os.environ.get("BOSE_GWID")
    if not gwid:
        pytest.skip("BOSE_GWID environment variable not set. Skipping fetchProductInformation test.")
        
    auth.getControlToken(email=os.environ.get("BOSE_EMAIL"), password=os.environ.get("BOSE_PASSWORD"), forceNew=True)
    product_info = auth.fetchProductInformation(gwid)
    assert product_info is not None, "Failed to fetch product information"
    assert "productID" in product_info, "productID key missing from product info"
    assert "productType" in product_info, "productType key missing from product info"
    assert "users" in product_info, "users key missing from product info"