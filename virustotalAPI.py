# Original author: Lucas Soares Pellizzaro on 2018-12-11

import re

_CONNECTION = None
_PROXYURL = ""
_APIKEY = ""

class ConnectionError(Exception):
	"""
	Exception raised by connection not started properly.
	Attributes:
		message -- explanation of the error
	"""
	def __init__(self):
		self.msg1 = "A connection has not been set,"
		self.msg2 = " use 'startConnection()' to start a connection"
		self.msg3 = " and 'setProxy(proxy_url)' if you are using a proxy."
		self.message = self.msg1+self.msg2+self.msg3

def _sendArtifact(p_baseurl, p_artifact):
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
	USER_AGENT = "vtAPI/1.0 (A Python interface to the public virustotal API)"
	headers = make_headers(keep_alive=False, user_agent=USER_AGENT)
	global _CONNECTION
	if(_PROXYURL != ""):
		from urllib3 import ProxyManager
		_CONNECTION = urllib3.ProxyManager(proxy_url=_PROXYURL, headers=headers)
	else:
		_CONNECTION = urllib3.PoolManager(headers=headers)

def setProxy(p_proxyurl):
	pattern = """(?:http|https)(?:\:\/\/)(?:[a-z]*(?:\.)?){5}(?:\:[0-9]{1,5})"""
	if(re.match(pattern,p_proxyurl)):
		global _PROXYURL
		_PROXYURL = p_proxyurl
	else:
		print("The provided proxy url is invalid.")

def setApiKey(p_apikey):
	pattern = """[a-z0-9]{64}"""
	if(re.match(pattern,p_apikey)):
		global _APIKEY
		_APIKEY = p_apikey
	else:
		print("The provided api key is invalid.")

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
			baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
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
			baseurl = "https://www.virustotal.com/vtapi/v2/file/report"
			return _sendArtifact(baseurl, p_filehash)
	except ConnectionError as e:
		print(e.message)
