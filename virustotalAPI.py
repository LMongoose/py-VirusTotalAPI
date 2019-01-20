# Original author: Lucas Soares Pellizzaro on 2018-12-20

_APIKEY = ""
_PROXYURL = ""
_CONNECTION = None

def _sendArtifact(p_baseurl, p_artifact):
	# Starts the request
	request_params = {
		"_APIKEY": _APIKEY,
		"resource": p_artifact
	}
	this_request = _CONNECTION.request("POST", url=p_baseurl, fields=request_params)
	# Checks the response status and returns output
	if(str(this_request.status) == "200"):
		import json
		json_raw = this_request.data.decode("utf-8")
		func_output = {
			"statuscode": 200,
			"output": json.loads(json_raw)["positives"]
		}
	else:
		func_output = {
			"statuscode": this_request.status,
			"output": None
		}
	return func_output

def startConnection():
	# Starts the connection
	import urllib3
	urllib3.disable_warnings()
	if(_PROXYURL != ""):
		import sys, platform
		os_architecture = "x86"
		if(platform.system() == "Windows"):
			if(sys.platform == "win64"):
				os_architecture = "x64"
		else:
			if(("amd64" in platform.release()) or ("x64" in platform.release())):
				os_architecture = "x64"
		pythonversion = "Python "+sys.version[:5]+" "+"("+os_architecture+")"
		opsysversion = platform.system()+" "+platform.release()
		sysinfo = pythonversion+" running on "+opsysversion

		from urllib3 import ProxyManager, make_headers
		headers = make_headers(keep_alive=False, user_agent="Urllib3 module for "+sysinfo)
		_CONNECTION = urllib3.ProxyManager(proxy_url=_PROXYURL, headers=headers)
	else:
		_CONNECTION = urllib3.PoolManager()

def setProxy(p_proxyurl):
	# TODO: validate p_proxyurl
	_PROXYURL = p_proxyurl
	start()

def setApiKey(p_apikey):
	# TODO: validate p_apikey
	_APIKEY = p_apikey

def scanUrl(p_url):
	"""
	Sends the url in 'p_url' to virustotal
	Returns a dict containing 'statuscode' 
	and 'output' with number of positives
	"""
	baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
	return _sendArtifact(baseurl, p_url)

def scanFile(p_filehash):
	"""
	Sends the file hash in 'p_filehash' 
	to virustotal (file hash must be SHA256)
	Returns a dict containing 'statuscode' 
	and 'output' with number of positives
	"""
	baseurl = "https://www.virustotal.com/vtapi/v2/file/report"
	return _sendArtifact(baseurl, p_filehash)