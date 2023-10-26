---
title : "CRTP Exam Review"
date: 2023-10-26 07:23:00 +0530
categories: [Red-Teaming-Exams,CRTP-Review]
tags: [active-directory,CRTP-exam]
---

![crtp-header](/assets/post_img/activedirectorylab.png)


# <span style="color:lightblue">介绍</span>

其实很早之前就已经通过了 Altered Security 的 CRTP (Certified Red Team Professional) 考试并获得了认证

如果你对CRTP不是很了解,可以点击下方链接

[CRTP](https://www.alteredsecurity.com/adlab)


# <span style="color:lightblue">准备</span>

![exam-prep](/assets/post_img/socute.gif)

因为我之前所拥有的技术栈未曾涉及  red teaming 以及 Active Directory 相关的知识

为了更好的过渡到CRTO以及拥抱red teaming,我选择了CRTP认证

***


CRTP 认证涵盖了广泛的基本主题
[详细内容](https://www.alteredsecurity.com/adlab)

深入研究了 Active Directory (AD) 枚举、本地权限提升、域权限提升、域权限维持、基于 Kerberos 的攻击向量、SQL Server 信任、防御和防御绕过等领域

通过 CRTP 深入了解这些基本概念，将能够使我更好地应对 CRTO CRTE 中更高级的内容

# <span style="color:lightblue">CRTP Lab 以及购买选项</span>

| 30 DAYS LAB | 60 DAYS LAB | 90 DAYS LAB | 30 DAYS LAB 延长 | 重考 |
| ----------- | ----------- | ----------- | ---------------- | ---- |
| $249        | $379        | $499        | $199             | $99  |



我的建议是没有任何基础的话60天lab也足以,我购买了30天的lab访问时长

当购买后24小时内会受到具体的实验室访问地址以及凭据



30天内可以随时随地访问实验室进行学习



***



访问形式有两种:

​	web

​	VPN


![](/assets/post_img/adlab.png)

```bash
因为现阶段 我的订阅已经到期了,所以无法进行相关的演示

登录后 大家可以点击 Generate Credentials 生成所需的凭据信息

或者可以访问左侧的 Access Lab Material 获取全部的资料


建议在那之前先仔细查看 Frequently Asked Questions QA

Flag Verification 为每一章节所需要提交的Flag值,可以理解为课后题

Certification Exam 当你觉得差不多了 就可以点击此模块 进行考试

Discord Link 有不懂的可以去Discord向别的师傅请教
```

![实验室材料](/assets/post_img/Frequently%20Asked%20Questions.png)

| CovenantC2                                               | CovenantC2的相关混淆配置文件       |
| -------------------------------------------------------- | ---------------------------------- |
| Diagrams                                                 | 实验室拓扑图以及所涉及攻击向量     |
| Old_CourseVideos                                         | 旧的课程视频 (不建议)              |
| Recordings                                               | 四个会议视频(建议)                 |
| WalkthroughVideos                                        | 每一章节的Walkthrough (手把手教学) |
| Attacking_and_Defending_ActiveDirectory - SlideNotes.pdf | 课件 带注释                        |
| Attacking_and_Defending_ActiveDirectory.pdf              | 课件 没注释                        |
| ConnectingToTheLab.pdf                                   | 如何连接实验室                     |
| LabManualV1.5.pdf                                        | 实验室手册                         |
| Tools.zip                                                | 实验室所需工具集                   |


# <span style="color:lightblue">考试经历</span>

## <span style="color:lightgreen">考试设置</span>

CRTP 考试提供按需开始的灵活性,无需提前安排

考试设置过程通常需要大约 10-15 分钟