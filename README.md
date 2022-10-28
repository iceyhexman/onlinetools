# onlinetools
## 师傅们溯源时候看清楚，不是所有部署了onlinetools的都是我哦。找人找清楚卅，其他人部署的这个项目也找我有点尬啦，别太菜了。

这是一款线上工具箱，收集整理了一些渗透测试过程中常见的需求（病句？）

现在已经包含的功能有：

在线cms识别|信息泄露|工控|系统|物联网安全|cms漏洞扫描|nmap端口扫描|子域名获取


# 部署方法

    git clone https://github.com/iceyhexman/onlinetools.git
    cd onlinetools
    pip3 install -r requirements.txt
    nohup python3 main.py &

# Docker 部署

    git clone https://github.com/iceyhexman/onlinetools.git
    cd onlinetools
    docker build -t onlinetools .
    docker run -d -p 8000:8000 onlinetools

浏览器打开

    http://localhost:8000/

# 说明
1.漏洞poc来自开源项目AngelSword，共320个，在此表示感谢

2.本工具仅限于进行漏洞验证，如若因此引起相关法律问题，概不负责。

# 已有POC
[POC](./poc.md)


# 运行截图 （部分）

![cmsreg](/img/cms.png)
![cmsvuln](/img/cmsaq.png)
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




