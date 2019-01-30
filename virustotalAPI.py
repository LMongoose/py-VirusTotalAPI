# Original author: Lucas Soares Pellizzaro on 2019-01-24

import time, re

_CONNECTION = None
_USERAGENT = ""
_INTERVAL = 1	# in seconds

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
		self.message = "An api key is needed to send requests to virustotal."

# Local functions
def _sendArtifact(p_baseurl, p_artifact):
	try:
		if(_APIKEY == ""):
			raise ApiKeyError
		else:
			time.sleep(_INTERVAL)
			# Starts the request
			request_params = {
				"apikey": _APIKEY,
				"resource": p_artifact
			}
			this_request = _CONNECTION.request("POST", url=p_baseurl, fields=request_params)
			# Checks the response status and returns output
			if(str(this_request.status) == "200"):
				import json
				json_raw = this_request.data.decode("utf-8")
				func_output = {
					"statuscode": 200,
					"output": json.loads(json_raw)
				}
			else:
				func_output = {
					"statuscode": this_request.status,
					"output": None
				}
			return func_output
	except ApiKeyError as e:
		print(e.message)

# Public functions
def startConnection():
	try:
		if(_USERAGENT==""):
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

def setProxy(p_proxyurl):
	pattern = """(?:http|https)(?:\:\/\/)(?:[a-z]*(?:\.)?){5}(?:\:[0-9]{1,5})"""
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

def setInterval(p_interval):
	if(type(p_interval) is float):
		global _INTERVAL
		_INTERVAL = p_interval
	else:
		print("The provided interval is not a real number.")

def setApiKey(p_apikey):
	pattern = """[a-z0-9]{64}"""
	if(re.match(pattern, p_apikey)):
		global _APIKEY
		_APIKEY = p_apikey
	else:
		print("The provided api key is invalid.")

# Request functions
def scanUrl(p_url):
	"""
	Sends the url in 'p_url' to virustotal
	Returns a dict containing 'statuscode' 
	and 'output' with number of positives
	"""
	try:
		if(_CONNECTION == None):
			raise ConnectionError
		else:
			filter_protocol = """(?:(?:(?:https|http|ftp|localhost|file)|(?:HTTPS|HTTP|FTP|LOCALHOST|FILE))(?:\:\/\/))"""
			filter_prefix = """(?:[a-zA-Z0-9\-]+[.])?"""
			filter_domain = """(?:[a-zA-Z0-9\-]+)"""
			filter_dot = """(?:[.])"""
			filter_suffix = """(?:[a-zA-Z0-9\-]+)"""
			filter_geoloc = """(?:[.][a-zA-Z0-9]{2})?"""
			filter_subdomains = """(?:(?:\/)(?:[a-zA-Z0-9\-\_\?\. ]+))*"""
			url_regex = filter_protocol+filter_prefix+filter_domain+filter_dot+filter_suffix+filter_geoloc+filter_subdomains
			if(not(re.match(url_regex, p_url))):
				raise UserInputError("url")
			else:
				baseurl = _BASE_APIURL+"url/report"
				return _sendArtifact(baseurl, p_url)
	except ConnectionError as e:
		print(e.message)

def scanFile(p_filehash):
	"""
	Sends the file hash in 'p_filehash' to 
	virustotal (file hash must be SHA256)
	Returns a dict containing 'statuscode' 
	and 'output' with number of positives
	"""
	try:
		if(_CONNECTION == None):
			raise ConnectionError
		else:
			hash_regex = """[0123456789abcdef]{64}"""
			if(not(re.match(hash_regex, p_account))):
				raise UserInputError("hash")
			else:
				baseurl = _BASE_APIURL+"file/report"
				return _sendArtifact(baseurl, p_filehash)
	except ConnectionError as e:
		print(e.message)