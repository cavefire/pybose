#! /usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Slighly modified version of the Gigya SDK for Python
https://github.com/SAP/gigya-python-sdk/tree/main
"""
from __future__ import unicode_literals
import sys

MAJOR_VERSION_INDEX = 0
MINOR_VERSION_INDEX = 1

PY_3 = sys.version_info[MAJOR_VERSION_INDEX] >= 3

PY_3_9_OR_GREATER = PY_3 and sys.version_info[MINOR_VERSION_INDEX] >= 9

if PY_3:
    import urllib.request
    from urllib.request import build_opener
    from urllib.request import HTTPHandler
    from urllib.request import ProxyHandler
    from urllib.request import install_opener
    from urllib.request import urlopen
    from http.client import HTTPSConnection
    from http.client import HTTPS_PORT
    from urllib.request import HTTPSHandler
    from urllib.parse import quote_plus
    from urllib.parse import urlparse
else:
    import urllib2
    from urllib2 import build_opener
    from urllib2 import HTTPHandler
    from urllib2 import ProxyHandler
    from urllib2 import install_opener
    from urllib2 import urlopen
    from httplib import HTTPSConnection
    from httplib import HTTPS_PORT
    from urllib2 import HTTPSHandler
    from urllib import quote_plus
    from urlparse import urlparse

import hmac
import time
import calendar
import socket
import os
import ssl
import copy

from hashlib import sha1
from base64 import b64decode, b64encode
from json import loads
from json import dumps as jsonstringify
from re import search
from random import randrange

if PY_3:
    string_types = str
    integer_types = int
else:
    string_types = basestring
    integer_types = (int, long)


class GSException(Exception):
    def __init__(self, value):
        self.errorMessage = value

    def __str__(self):
        return repr(self.value)


class GSRequest():
    DEFAULT_API_DOMAIN = "us1.gigya.com"
    VERSION = "3.5.2"
    caCertsPath = os.path.join(os.path.dirname(__file__), "cacert.pem")

    _domain = "accounts.us1.gigya.com"
    _path = ""
    _traceLog = []
    _method = ""
    _proxy = ""
    _host = ""

    _apiKey = ""
    _secretKey = ""
    _userKey = ""
    _params = {}
    _useHTTPS = False
    _apiDomain = DEFAULT_API_DOMAIN

    def __init__(self, apiKey=None, secretKey=None, apiMethod=None, params=None, useHTTPS=False, userKey=None, enable_host_check=True):
        """
         Constructs a request using the apiKey and secretKey.
         @param apiKey
         @param secretKey
         @param apiMethod the api method (including namespace) to call. for example: socialize.getUserInfo
         If namespaces is not supplied "socialize" is assumed
         @param params the request parameters
         @param useHTTPS useHTTPS set this to true if you want to use HTTPS.
         @param userKey A key of an admin user with extra permissions.
         @param enable_host_check Hostcheck can be disabled by passing enable_host_check=false when using HTTPS. Can be necessary when using proxy. Default is True
         If this parameter is provided, then the secretKey parameter is assumed to be the admin user's secret key and not the site's secret key.
        """

        if apiMethod is None:
            return

        self._method = apiMethod

        if params is None:
            self._params = {}
        elif isinstance(params, dict):
            self._params = copy.copy(params)
        elif isinstance(params, string_types):
            self._params = Utils.jsonparse(params)
        else:
            self._params = dict([k, v.encode('utf-8')] for k, v in params.items())

        self._domain = self._params.get("_host", self._domain)
        self._useHTTPS = useHTTPS
        self._apiKey = apiKey
        self._secretKey = secretKey
        self._userKey = userKey
        self._traceLog = list()
        self._enableHostCheck = enable_host_check
        self.traceField("apiMethod", apiMethod)
        self.traceField("apiKey", apiKey)

    def setParam(self, param, val):
        self._params[param] = val

    def getParams(self):
        return self._params

    def setAPIDomain(self, apiDomain=None):
        if apiDomain is None:
            self._apiDomain = self.DEFAULT_API_DOMAIN
        else:
            self._apiDomain = apiDomain

    def setProxy(self, proxy):
        self._proxy = proxy
        self.traceField("proxy", proxy)

    def send(self, timeout=None):
        """Send the request synchronously"""

        if self._method[0:1] == "/":
            self._method = self._method[1:]

        if self._method.find(".") == -1:
            self._domain = "socialize." + self._apiDomain
            self._path = "/socialize." + self._method
        else:
            tokens = self._method.split(".")
            self._domain = tokens[0] + "." + self._apiDomain
            self._path = "/" + self._method

        format = self._params.get("format", None)

        if format is None:
            format = "json"
            self.setParam("format", format)
        if timeout:
            timeout = float(timeout)
            self.traceField("timeout", timeout)

        if (self._method is None or (self._apiKey is None and self._userKey is None)):
            return GSResponse(self._method, None, self._params, 400002, None, self._traceLog)

        if (self._useHTTPS and not os.path.isfile(GSRequest.caCertsPath)):
            return GSResponse(self._method, None, self._params, 400003, None, self._traceLog)

        try:
            self.setParam("httpStatusCodes", "false")
            self.traceField("apiKey", self._apiKey)
            self.traceField("apiMethod", self._method)
            self.traceField("params", self._params)
            self.traceField("useHTTPS", self._useHTTPS)
            self.traceField("userKey", self._userKey)
            responseStr = self.sendRequest("POST", self._host, self._path, self._params, self._apiKey, self._secretKey, self._useHTTPS, timeout, self._userKey, self._enableHostCheck)

            return GSResponse(self._method, responseStr, None, 0, None, self._traceLog)

        except Exception as ex:
            errCode = 500000
            errMsg = str(ex)
            length = len("Operation timed out")

            if (errMsg[0:length] == "Operation timed out"):
                errCode = 504002
                errMsg = "Request Timeout"

            return GSResponse(self._method, None, self._params, errCode, errMsg, self._traceLog)

    def sendRequest(self, httpMethod, domain, path, params, token, secret=None, useHTTPS=False, timeout=None, userKey=None, enable_host_check=True):

        params["sdk"] = "ios_swift_1.0.8"
        # prepare query params
        protocol = "https" if (useHTTPS or not secret) else "http"
        resourceURI = protocol + "://" + self._domain + path

        timestamp = calendar.timegm(time.gmtime())

        # unique token
        nonce = str(SigUtils.currentTimeMillis()) + str(randrange(1000))

        if userKey:
            params["userKey"] = userKey

        if secret:
            params["apiKey"] = token
            params["timestamp"] = timestamp
            params["nonce"] = nonce

            # signature
            signature = self.getOAuth1Signature(secret, httpMethod, resourceURI, useHTTPS, params)
            params["sig"] = signature
        else:
            params["oauth_token"] = token

        # get rest response.
        res = self.curl(resourceURI, params, timeout, enable_host_check)

        return res


    def curl(self, url, params=None, timeout=None, enable_host_check=True):

        queryString = self.buildQS(params)

        self.traceField("URL", url)
        self.traceField("postData", queryString)

        proto = "https" if self._useHTTPS else "http"

        if self._proxy:
            opener = build_opener(
                HTTPHandler(),
                ValidHTTPSHandler(enable_host_check), # maybe always send False???
                ProxyHandler({proto: self._proxy}))
        else:
            opener = build_opener(
                HTTPHandler(),
                ValidHTTPSHandler(enable_host_check))

        queryString = queryString.encode('utf-8')

        currentOpener = urllib.request._opener if PY_3 else urllib2._opener
        install_opener(opener)

        if timeout:
            response = urlopen(url, queryString, timeout)
        else:
            response = urlopen(url, queryString, context=ssl._create_unverified_context())

        install_opener(currentOpener)

        result = response.read()
        result = result.decode('utf-8')

        return result

    def buildQS(self, params):
        """Converts a params dictionary to a sorted query string"""
        queryString = ""
        amp = ""
        # keys = params.keys()
        keys = list(params.keys())
        keys.sort()
        for key in keys:
            value = params.get(key)
            if value is not None:
                queryString += amp + key + "=" + self.UrlEncode(value)
                amp = "&"

        return queryString

    def getOAuth1Signature(self, key, httpMethod, url, isSecureConnection, requestParams):
        # Create the BaseString.
        baseString = self.calcOAuth1BaseString(httpMethod, url, isSecureConnection, requestParams)
        self.traceField("baseString", baseString)

        return SigUtils.calcSignature(baseString, key)

    def calcOAuth1BaseString(self, httpMethod, url, isSecureConnection, requestParams):
        normalizedUrl = ""
        u = urlparse(url)

        if isSecureConnection:
            protocol = "https"
        else:
            protocol = u.scheme.lower()

        port = u.port

        normalizedUrl += protocol + "://"
        normalizedUrl += u.hostname.lower()

        if port != None and ((protocol == "http" and port != 80) or (protocol == "https" and port != 443)):
            normalizedUrl += ':' + port

        normalizedUrl += u.path

        # Create a sorted list of query parameters
        queryString = self.buildQS(requestParams)

        # Construct the base string from the HTTP method, the URL and the parameters
        baseString = httpMethod.upper() + '&' + self.UrlEncode(normalizedUrl) + '&' + self.UrlEncode(queryString)

        return baseString

    def UrlEncode(self, value):
        if value is None:
            return value
        elif isinstance(value, integer_types):
            return str(value)
        else:
            if isinstance(value, dict) or isinstance(value, list):
                str_value = jsonstringify(value)
            else:
                str_value = value.encode('utf-8')

            return quote_plus(str_value).replace("+", "%20").replace("%7E", "~")

    def traceField(self, name, value):
        if value:
            self._traceLog.append(str(name) + "=" + repr(value))

    @staticmethod
    def setCACertsPath(path):
        GSRequest.caCertsPath = path


class GSResponse():
    """
     Wraps the server's response.
     If the request was sent with the format set to "json", the getData() will return null and you should use getResponseText() instead.
     We only parse response text into a dictionary if request format is set "json."
    """

    errorCode = 0
    errorMessage = None
    rawData = ""
    data = {}
    params = None
    method = None
    traceLog = []
    errorMsgDic = {}
    errorMsgDic[400002] = "Required parameter is missing"
    errorMsgDic[500000] = "General server error"

    def getErrorCode(self):
        return self.errorCode

    def getErrorMessage(self):
        if self.errorMessage:
            return self.errorMessage
        else:
            if (self.errorCode == 0) or (not self.errorMsgDic.get(self.errorCode)):
                return ""
            else:
                return self.errorMsgDic.get(self.errorCode)

    def getResponseText(self):
        if (type(self.rawData) == "bytes"):
            self.rawData = self.rawData.decode(encoding="utf-8", errors="strict")
        return self.rawData

    def getData(self):
        if (type(self.data) == "bytes"):
            self.data = self.data.decode(encoding="utf-8", errors="strict")
        return self.data

    def getObject(self, key):
        return self.data.get(key)

    def traceField(self, name, value):
        if value:
            self.traceLog.append(str(name) + "=" + repr(value))

    def __init__(self, method, responseText=None, params=None, errorCode=None, errorMessage=None, traceLog=None):
        self.traceLog = traceLog
        self.method = method

        if params:
            self.params = params
        else:
            self.params = {}

        if responseText:
            self.traceField("responseText", responseText)

            self.rawData = responseText.encode('utf-8')

            if (responseText.lstrip().find('{') != -1):
                self.data = Utils.jsonparse(responseText)

                if self.data:
                    self.errorCode = self.data.get("errorCode")
                    self.errorMessage = self.data.get("errorMessage")

            else:
                matches = search(r"<errorCode>([^>]+)</errorCode>", self.rawData)
                if matches:
                    errCodeStr = matches.group(1)
                    if errCodeStr:
                        self.errorCode = int(errCodeStr)
                        matches = search(r"<errorMessage>([^>]+)</errorMessage>", self.rawData)
                        if matches:
                            self.errorMessage = matches.group(1)

        else:
            self.errorCode = errorCode
            self.errorMessage = errorMessage if errorMessage != None else self.getErrorMessage()
            self.populateClientResponseText()
            self.traceField("responseText", self.rawData)

    def populateClientResponseText(self):
        if self.params.get("format") == 'json':
            self.rawData = "{errorCode:" + str(self.errorCode) + ",errorMessage:\"" + self.errorMessage + "\"}"
        else:
            sb = [
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<" + self.method + "Response xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"urn:com:gigya:api http://socialize-api.gigya.com/schema\" xmlns=\"urn:com:gigya:api\">",
                "<errorCode>" + str(self.errorCode) + "</errorCode>",
                "<errorMessage>" + self.errorMessage + "</errorMessage>",
                "</" + self.method + "Response>"
            ]
            self.rawData = "\r\n".join(sb)

    def getLog(self):
        return ", ".join(self.traceLog)

    def __str__(self):
        sb = ""
        sb += "\terrorCode:"
        sb += str(self.errorCode)
        sb += "\n\terrorMessage:"
        sb += self.errorMessage
        sb += "\n\tdata:"
        sb += str(self.data)
        return sb


class ValidHTTPSConnection(HTTPSConnection):
    default_port = HTTPS_PORT

    def __init__(self, *args, **kwargs):
        HTTPSConnection.__init__(self, *args, **kwargs)
        self._context = kwargs.get('context')

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)

        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class ValidHTTPSHandler(HTTPSHandler):
    def __init__(self, enable_host_check=True):
        super().__init__()
        self._enableHostCheck = enable_host_check

    def https_open(self, req):
        return self.do_open(self.get_connection, req)

    def get_connection(self, host, timeout):
        return ValidHTTPSConnection(host, timeout = timeout, context = self.create_context())

    def create_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


class SigUtils():

    @staticmethod
    def validateUserSignature(UID, timestamp, secret, signature, expiration=None):
        baseString = timestamp + "_" + UID
        expectedSig = SigUtils.calcSignature(baseString, secret)
        if expiration is None:
            return expectedSig == signature
        else:
            expired = SigUtils.signatureTimestampExpired(timestamp, expiration)
            return not expired and expectedSig == signature

    @staticmethod
    def validateUserSignatureWithExpiration(UID, timestamp, secret, signature, expiration):
        expired = SigUtils.signatureTimestampExpired(timestamp, expiration)
        signatureValidated = SigUtils.validateUserSignature(UID, timestamp, secret, signature)
        return not expired and signatureValidated

    @staticmethod
    def validateFriendSignature(UID, timestamp, friendUID, secret, signature, expiration=None):
        baseString = timestamp + "_" + friendUID + "_" + UID
        expectedSig = SigUtils.calcSignature(baseString, secret)
        if expiration is None:
            return expectedSig == signature
        else:
            expired = SigUtils.signatureTimestampExpired(timestamp, expiration)
            return not expired and expectedSig == signature

    @staticmethod
    def validateFriendSignatureWithExpiration(UID, timestamp, friendUID, secret, signature, expiration):
        expired = SigUtils.signatureTimestampExpired(timestamp, expiration)
        signatureValidated = SigUtils.validateFriendSignature(UID, timestamp, friendUID, secret, signature)
        return not expired and signatureValidated

    @staticmethod
    def getDynamicSessionSignature(gltCookie, timeoutInSeconds, secret):
        expirationTimeUnixMS = calendar.timegm(time.gmtime()) + timeoutInSeconds
        expirationTimeUnixString = str(expirationTimeUnixMS)
        unsignedExpString = gltCookie + "_" + expirationTimeUnixString
        signedExpString = SigUtils.calcSignature(unsignedExpString, secret)
        ret = expirationTimeUnixString + "_" + signedExpString
        return ret

    @staticmethod
    def getDynamicSessionSignatureUserSigned(gltCookie, timeoutInSeconds, userKey, secret):
        expirationTimeUnixMS = calendar.timegm(time.gmtime()) + timeoutInSeconds
        expirationTimeUnixString = str(expirationTimeUnixMS)
        unsignedExpString = gltCookie + "_" + expirationTimeUnixString + "_" + userKey
        signedExpString = SigUtils.calcSignature(unsignedExpString, secret)
        ret = expirationTimeUnixString + "_" + userKey + "_" + signedExpString
        return ret

    @staticmethod
    def calcSignature(baseString, key):
        encodedBase = baseString.encode("utf-8")
        encodedKey = key.encode('utf-8')
        rawHmac = hmac.new(b64decode(encodedKey), encodedBase, sha1).digest()
        signature = b64encode(rawHmac)
        signature = signature.decode('utf-8')

        return signature

    @staticmethod
    def currentTimeMillis():
        return int(round(time.time() * 1000))

    @staticmethod
    def signatureTimestampExpired(signatureTimestampExpired, expiration):
        now = int(round(time.time()))
        timestamp = int(signatureTimestampExpired)
        return abs(now - timestamp) > expiration

class Utils():

    @staticmethod
    def jsonparse(source):
        if PY_3_9_OR_GREATER:
            return loads(source)
        else:
            return loads(source, encoding='utf-8')

