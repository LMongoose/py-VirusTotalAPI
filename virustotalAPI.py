# Original author: Lucas Soares Pellizzaro on 2018-12-20

import urllib3
urllib3.disable_warnings()

APIKEY = ""
PROXY_URL = ""

# Starts the connection
if PROXY_URL != "":
	import sys, platform
	os_architecture = "x86"
	if(platform.system() == "Windows"):
		if(sys.platform == "win64"):
			os_architecture = "x64"
	else:
		if("amd64" in platform.release() or "x64" in platform.release()):
			os_architecture = "x64"

	pythonversion = "Python "+sys.version[:5]+" "+"("+os_architecture+")"
	opsysversion = platform.system()+" "+platform.release()
	sysinfo = pythonversion+" "+"running on"+" "+opsysversion

	from urllib3 import ProxyManager, make_headers
	headers = make_headers(keep_alive=False, user_agent="Urllib3 module for "+sysinfo)
	connection = urllib3.ProxyManager(proxy_url=PROXY_URL, headers=headers)
else:
	connection = urllib3.PoolManager()

def getPositives(p_url):
	"""
	Sends the url in 'p_url' to virustotal
	Returns a dict containing 'statuscode' 
	and 'output' with number of positives
	"""
	# Starts the request
	request_params = {
		"apikey": APIKEY,
		"resource": p_url
	}
	baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
	this_request = connection.request("POST", url=baseurl, fields=request_params)

	# Checks the response status and returns output
	if str(this_request.status) == "200":
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