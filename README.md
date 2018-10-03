# onlinetools
这是一款线上工具箱，收集整理了一些渗透测试过程中常见的需求（病句？）

现在已经包含的功能有：

在线cms识别|旁站|c段|信息泄露|工控|系统|物联网安全|cms漏洞扫描|nmap端口扫描|子域名获取


# 部署方法

    git clone https://github.com/iceyhexman/onlinetools.git
    cd onlinetools
    pip3 install -r requirements.txt
    nohup python3 main.py &

浏览器打开

    http://localhost:8000/


# 说明
1.漏洞poc来自开源项目AngelSword，共320个，在此表示感谢

2.本工具仅限于进行漏洞验证，如若因此引起相关法律问题，概不负责。

# 已有POC
[POC](./poc.md)


# 运行截图

![cmsreg](/img/cms.png)
![cmsvuln](/img/cmsaq.png)
![pang](/img/pang.png)
![information](/img/information.png)
![subdomain](/img/subdomain.png)
![nmap](/img/nmap.png)



# demo
http://tools.hexlt.org/

别滥用就行

# bug & 下一版本

有什么建议或者要修改的地方请直接提issue就行
懒癌犯了好几个月了...
下一版本最主要的变化应该是插件中心吧..各位dalao欢迎提poc(`・ω・´)




