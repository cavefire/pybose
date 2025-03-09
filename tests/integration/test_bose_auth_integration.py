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

@pytest.mark.integration
def test_get_ids_integration(auth):
    """
    Test the _get_ids() method by calling the live API.
    """
    ids = auth._get_ids()
    assert ids is not None, "Failed to retrieve IDs"
    assert "gmid" in ids and ids["gmid"] is not None, "GMID not found in response"
    assert "ucid" in ids and ids["ucid"] is not None, "UCID not found in response"

@pytest.mark.integration
def test_get_control_token_integration(auth):
    """
    Test the complete token retrieval flow via getControlToken.
    This test verifies that a valid JWT is returned.
    """
    email = os.environ.get("BOSE_EMAIL")
    password = os.environ.get("BOSE_PASSWORD")
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    assert "access_token" in token, "Access token not found"
    assert "refresh_token" in token, "Refresh token not found"
    assert "bose_person_id" in token, "Bose person ID not found"
    
    # TODO: figure out a way to verify the token signature
    decoded = jwt.decode(token["access_token"], options={"verify_signature": False})
    assert "exp" in decoded, "Expiration not found in token"
    assert "tokenName" in decoded and decoded["tokenName"] == "access_token", "Token name not found or incorrect"
    assert decoded["exp"] > time.time(), "Token is expired"

@pytest.mark.integration
def test_refresh_token_integration(auth):
    """
    Test refreshing the access token using a valid refresh token.
    """
    email = os.environ.get("BOSE_EMAIL")
    password = os.environ.get("BOSE_PASSWORD")
    token = auth.getControlToken(email=email, password=password, forceNew=True)
    assert token is not None, "Failed to retrieve control token"
    assert "access_token" in token, "Access token not found"
    assert "refresh_token" in token, "Refresh token not found"
    
    refreshed = auth.do_token_refresh(token["refresh_token"])
    assert refreshed is not None, "Failed to refresh token"
    assert "access_token" in refreshed, "Access token not found"
    assert "refresh_token" in refreshed, "Refresh token not found"
    assert "bose_person_id" in refreshed, "Bose person ID not found"
    
    assert refreshed["access_token"] != token["access_token"], "Access token was not refreshed"
    assert refreshed["refresh_token"] != token["refresh_token"], "Refresh token was not refreshed"

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