#!/usr/bin/env python
# Original author: Lucas Soares Pellizzaro on 2019-04-30

"""
Module to provide a connection to virustotal.
It contains functions to send artifacts to be scanned
and returns the scan results.
"""

import time, re, json

_CONNECTION = None
_USERAGENT = ""
_INTERVAL = 3 # in seconds
_PROXY_ENABLED = False
_PROXY_URL = ""
_PROXY_AUTH_ENABLED = False
_PROXY_AUTH = ""
_APIKEY = ""
_BASE_APIURL = "https://www.virustotal.com/vtapi/v2/"

# Exceptions
class ConnectionError(Exception):
	def __init__(self):
		self.message = "A connection has not been started properly."

class UserAgentError(Exception):
	def __init__(self):
		self.message = "The user agent has not been set."

class ApiKeyError(Exception):
	def __init__(self):
		self.message = "An api key is required to send requests to virustotal."

class UserInputError(Exception):
	def __init__(self, p_type):
		self.message = "The provided "+p_type+" is invalid!"

# Local functions
def _sendArtifact(p_baseurl, p_params):
	try:
		if(_CONNECTION == None):
			raise ConnectionError
		if(_APIKEY == ""):
			raise ApiKeyError
		time.sleep(_INTERVAL)
		_resp = _CONNECTION.request("GET", p_baseurl, p_params, headers=None)
		if(str(_resp.status) == "200"):
			func_output = {
				"statuscode": 200,
				"output": json.loads(_resp.data.decode("utf-8"))
			}
		else:
			func_output = {
				"statuscode": _resp.status,
				"output": None
			}
		return func_output
	except ConnectionError as e:
		print(e.message)
	except ApiKeyError as e:
		print(e.message)

# Public functions
def startConnection():
	"""
	Apply the current configurations and try
	to start a new connection with virustotal.
	"""
	try:
		if(_USERAGENT == ""):
			raise UserAgentError
		else:
			import urllib3
			urllib3.disable_warnings()
			from urllib3 import make_headers
			global _CONNECTION
			headers = make_headers(keep_alive=False, user_agent=_USERAGENT)
			if(_PROXY_ENABLED == True):
				if(_PROXY_AUTH_ENABLED == True):
					headers = make_headers(keep_alive=False, user_agent=_USERAGENT, proxy_basic_auth=_PROXY_AUTH)
				from urllib3 import ProxyManager
				_CONNECTION = urllib3.ProxyManager(proxy_url=_PROXY_URL, headers=headers)
			else:
				_CONNECTION = urllib3.PoolManager(headers=headers)
	except UserAgentError as e:
		print(e.message)

def setUserAgent(p_useragent):
	if(type(p_useragent) is str):
		global _USERAGENT
		_USERAGENT = p_useragent
	else:
		print("The provided user agent is not a string.")

def setInterval(p_interval):
	if(type(p_interval) is float):
		global _INTERVAL
		_INTERVAL = p_interval
	else:
		print("The provided interval is not a real number.")

def setProxy(p_proxyurl):
	pattern = r"""(?:http|https)(?:\:\/\/)(?:[a-z]*(?:\.)?){5}(?:\:[0-9]{1,5})"""
	if(re.match(pattern, p_proxyurl)):
		global _PROXY_URL
		_PROXY_URL = p_proxyurl
	else:
		print("The provided proxy url is invalid.")

def enableProxy():
	global _PROXY_ENABLED
	_PROXY_ENABLED = True

def disableProxy():
	global _PROXY_ENABLED
	_PROXY_ENABLED = False

def setProxyAuth(p_username, p_password):
	global _PROXY_AUTH
	_PROXY_AUTH = p_username+":"+p_password

def enableProxyAuth():
	global _PROXY_AUTH_ENABLED
	_PROXY_AUTH_ENABLED = True

def disableProxyAuth():
	global _PROXY_AUTH_ENABLED
	_PROXY_AUTH_ENABLED = False

def setApiKey(p_apikey):
	pattern = r"""[a-z0-9]{64}"""
	if(re.match(pattern, p_apikey)):
		global _APIKEY
		_APIKEY = p_apikey
	else:
		print("The provided api key is invalid.")

# Request functions
def scanUrl(p_url):
	"""
	Sends the url in 'p_url' to virustotal.
	Returns a dict containing 'statuscode' 
	and 'output' with scan details.
	"""
	try:
		protocol = r"""(?:(?:(?:https|http|ftp|localhost|file)|(?:HTTPS|HTTP|FTP|LOCALHOST|FILE))(?:\:\/\/))"""
		prefix = r"""(?:[a-zA-Z0-9\-]+[.])?"""
		domain = r"""(?:[a-zA-Z0-9\-]+)"""
		dot = r"""(?:[.])"""
		suffix = r"""(?:[a-zA-Z0-9\-]+)"""
		geoloc = r"""(?:[.][a-zA-Z0-9]{2})?"""
		subdomains = r"""(?:(?:\/)(?:[a-zA-Z0-9\-\_\?\. ]+))*"""
		pattern = protocol+prefix+domain+dot+suffix+geoloc+subdomains
		if(not(re.match(pattern, p_url))):
			raise UserInputError("url")
		_fields = {
			"apikey": _APIKEY,
			"resource": p_url
		}
		return _sendArtifact(_BASE_APIURL+"url/report", _fields)
	except UserInputError as e:
		print(e.message)
	except Exception as e:
		print("Unexpected error sending url to virustotal!")

def scanFile(p_filehash):
	"""
	Sends the file hash in 'p_filehash' to virustotal
	(file hash can be MD5 or SHA1 or SHA256).
	Returns a dict containing 'statuscode' 
	and 'output' with scan details.
	"""
	try:
		hash_regex = """[0123456789abcdef]{64}"""
		if(not(re.match(hash_regex, p_filehash))):
			raise UserInputError("hash")
		_fields = {
			"apikey": _APIKEY,
			"resource": p_filehash
		}
		return _sendArtifact(_BASE_APIURL+"file/report", _fields)
	except UserInputError as e:
		print(e.message)
	except Exception as e:
		print("Unexpected error sending file to virustotal!")

def scanDomain(p_domain):
	"""
	Sends the domain in 'p_domain' to virustotal.
	Returns a dict containing 'statuscode' 
	and 'output' with scan details.
	"""
	try:
		_fields = {
			"apikey": _APIKEY,
			"domain": p_domain
		}
		return _sendArtifact(_BASE_APIURL+"domain/report", _fields)
	except Exception:
		print("Unexpected error sending file to virustotal!")

def scanIp(p_ip):
	"""
	Sends the ip in 'p_ip' to virustotal.
	Returns a dict containing 'statuscode' 
	and 'output' with scan details.
	"""
	try:
		_pattern = r"""[0-9]+(?:\.[0-9]+){3}[:]{0,1}[0-9]{0,5}"""
		if(not(re.match(_pattern, p_ip))):
			raise UserInputError("ip")
		_fields = {
			"apikey": _APIKEY,
			"ip": p_ip
		}
		return _sendArtifact(_BASE_APIURL+"ip-address/report", _fields)
	except UserInputError as e:
		print(e.message)
	except Exception:
		print("Unexpected error sending file to virustotal!")