#!/usr/bin/env python
#
# This script will take CSV input (IP reputation database) and push into 
# Riverbed Application Firewall blacklist
#
# Uses gevent + requests for asynchronous HTTP concurrency
#
# @gitrc
#


import gevent.monkey
gevent.monkey.patch_all()
from gevent import Timeout
import sys
import requests, json
import re

af_url = 'http://localhost:8087/api/af/1.2/blacklistedips/'  # 127.0.0.1:8087 via SSH tunnel direct WAF API
#af_url = 'https://x.x.x.x:9070/api/af/1.2/blacklistedips/' # production front door REST API proxy
af_user = 'admin'
af_pass = 'admin'

filename = '/tmp/list.txt'
lines = [line.strip() for line in open(filename)]

targets = []
for line in lines:
	mo = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
     	if mo:
        	targets.append(mo.group(0) + '/32')


r = requests.get(af_url, timeout=30, auth=(af_user, af_pass), verify=False)
data = r.json()

currents = []
for entry in data['blacklist']:
    currents.append(str(entry['ip_range']))  # str because of unicode

print "DEBUG: There are %s IP addresses currently in the blacklist." % (len(currents))



## BEGIN GEVENTS
timeout = Timeout(10)
errors = 0

## DELETE requests to prune the blacklist

def delete(target):
 global errors
 with Timeout(10):
	try:
		response = requests.request('DELETE', af_url + target, timeout=5, auth=(af_user, af_pass), verify=False)
		if response.status_code == 200:
			print "OK: " + target
		else:
			errors += 1
			print "ERROR: " + target
	except:
		errors += 1
		print "ERROR: " + target

workers = []
limit = 2
counter = 0
for target in currents:
    if not target in targets:
	    if counter < limit:
		target = target.replace('/32', '-32')
	        workers.append(gevent.spawn(delete, target))
	        counter += 1
	    else:
	        gevent.joinall(workers)
	        workers = []
	        counter = 0
gevent.joinall(workers)

## PUT requests to populate the blacklist


def fetch(target, payload):
 global errors
 with Timeout(10):
        try:
		response = requests.request('PUT', af_url + target, timeout=10, auth=(af_user, af_pass), verify=False, data=payload)
		if response.status_code == 200:
			print "OK: " + target
		else:
			errors += 1
			print "ERROR: " + target
	except:
		errors += 1
		print "ERROR: " + target

workers = []
limit = 10
counter = 0

for target in targets:
	if not target in currents:
	   if counter < limit:
		payload = {'ip_range': target, 'ttl': '86400'}
		target = target.replace('/32', '-32')
                workers.append(gevent.spawn(fetch, target, payload))
                counter += 1
           else:
                gevent.joinall(workers)
                workers = []
                counter = 0

gevent.joinall(workers)

print "DEBUG: Job finished with %s errors." % (errors)
