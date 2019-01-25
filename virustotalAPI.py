# Original author: Lucas Soares Pellizzaro on 2019-01-24

import time, re

# Constants
_CONNECTION = None
_USERAGENT = ""
_INTERVAL = 1
_PROXYURL = ""
_APIKEY = ""
_BASE_APIURL = "https://www.virustotal.com/vtapi/v2/"

# Exceptions
class ConnectionError(Exception):
	"""
	Exception raised by connection not started properly.
	Attributes:
		message -- explanation of the error
	"""
	def __init__(self):
		_msg1 = "A connection has not been set,"
		_msg2 = " use 'startConnection()' to start a connection"
		_msg3 = " and 'setProxy(proxy_url)' if you are using a proxy."
		self.message = _msg1+_msg2+_msg3

# Local functions
def _sendArtifact(p_baseurl, p_artifact):
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

# Public functions
def startConnection():
	import urllib3
	urllib3.disable_warnings()
	from urllib3 import make_headers
	if(_USERAGENT==""):
		print("The user agent has not been set.")
	else:
		headers = make_headers(keep_alive=False, user_agent=_USERAGENT)
		global _CONNECTION
		if(_PROXYURL != ""):
			from urllib3 import ProxyManager
			_CONNECTION = urllib3.ProxyManager(proxy_url=_PROXYURL, headers=headers)
		else:
			_CONNECTION = urllib3.PoolManager(headers=headers)

def setProxy(p_proxyurl):
	pattern = """(?:http|https)(?:\:\/\/)(?:[a-z]*(?:\.)?){5}(?:\:[0-9]{1,5})"""
	if(re.match(pattern, p_proxyurl)):
		global _PROXYURL
		_PROXYURL = p_proxyurl
	else:
		print("The provided proxy url is invalid.")

def setUserAgent(p_useragent):
	global _USERAGENT
	_USERAGENT = p_useragent

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
			baseurl = _BASE_APIURL+"file/report"
			return _sendArtifact(baseurl, p_filehash)
	except ConnectionError as e:
		print(e.message)