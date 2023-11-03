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

有一个出站代理服务器 - 如果您无法连接回来，请检查您的有效负载是否支持代理
检查*人们*犯的常见错误、弱密码、跨不同帐户重复使用密码
假设实验室中有用户活动，因此后门是有意义的
```

---

