---
title: "About this Blog"
description: "A deep dive into the manifest and decompiled Java code of a recent credential harvesting campaign."
date: 2024-03-11T13:17:00+05:30
tags: ["malware", "android", "reversing"]
---

## Static Analysis

MD5: 689ff2c6f94e31abba1ddebf68be810e

###### General Key Points:
- The file is not packed
- Header sections raw sizes and virtual sizes match within the limits
- The file is well known to AV signatures on VT

##### strings/floss:
@user-agent
@tables.nim(1103, 13) `len(t) ==
    L` the length of the table changed while iterating over it
@SSL support is not available. Cannot connect over SSL. Compile with -d:ssl to enable.
@https
@No uri scheme supplied.
InternetOpenW
InternetOpenUrlW
@wininet
@wininet
MultiByteToWideChar
@kernel32
@kernel32
MessageBoxW
@user32
@user32
@[+] what command can I run for you
@[+] online
@NO SOUP FOR YOU
@\mscordll.exe
@Nim httpclient/1.0.6
@/msdcorelib.exe
@AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
@intrt explr
@http://serv1.ec2-102-95-13-2-ubuntu.local

###### Host based indicators:


After execution, the malware creates the following file (mscordll.exe):
![[Pasted image 20250803164257.png]]
![[Pasted image 20250803164354.png]]
at the startup location in appdata

We then see multiple ports are being opened by the malware to reach an external site:
![[Pasted image 20250803164901.png]]

We test it by using TCPView :
![[Pasted image 20250803164947.png]]
We see that port 5555 is open by the process in listen mode. 
We then proceed to the linux remnux machine to test a connection by using netcat:
![[Pasted image 20250803165732.png]]

We try to run the whoami command:
![[Pasted image 20250803165925.png]]

We also see that the information being sent is encoded in base64.

The file looks for the command file in the machine and exceutes it:
![[Pasted image 20250803170121.png]]

###### Network based indicators:
###### Running the command while InetSim is offline (No internet connectivity):

- A message box pops:

![[Pasted image 20250803163405.png]]

###### Running the command while InetSim is on (internet connectivity):

![[Pasted image 20250803163024.png]]

- A network connection has been made to **serv1.ec2-102-95-13-2-ubuntu[.]local**
- A file named msdcorelib.exe was downloaded.
- The user agent is Nim http client.



Summary:

This malicious executable is a dropper for a second stage malware downloaded from the attacker URL.



